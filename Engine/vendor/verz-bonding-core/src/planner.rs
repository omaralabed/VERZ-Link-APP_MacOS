//! Minimum-cost repair rates.
//!
//! A protected failure ("unit") is a set of links that may fail together: one
//! link, links behind one ISP, or modems that were seen failing together. If
//! the unit fails, the links outside it must still deliver `required` repairs
//! per second, enough to rebuild what the unit was carrying:
//!
//! ```text
//! minimize   sum_j cost_j * rate_j
//! subject to sum_{j not in u} success_j * rate_j >= required_u   for every unit u
//!            0 <= rate_j <= spare_j
//! ```
//!
//! With N equal links and every single-link failure protected, the optimum is
//! rate_j = share / (N - 1): a total of N/(N-1) times the stream instead of N
//! times for full copies.
//!
//! Solved exactly with the simplex method on the dual problem, whose origin
//! is always feasible. A unit that no combination of links can cover keeps an
//! elastic deficit at a prohibitive price, so the rest is still protected.
//!
//! Equal links give many optimal solutions, and a vertex of the simplex puts
//! everything on one of them. Failures that nobody predicted hit a single
//! link, so the repairs should be spread: the plan is the average of the
//! optimal solutions found when each link in turn is made very slightly
//! cheaper, which is still optimal and favours no link.

#[derive(Clone, Debug)]
pub struct PlanLink {
    /// Fraction of packets on this link that arrive.
    pub success: f64,
    /// Repairs per second this link can still carry.
    pub spare: f64,
    /// Relative cost per repair (metered links are expensive).
    pub cost: f64,
}

#[derive(Clone, Debug)]
pub struct Unit {
    /// Indices into the `links` slice that fail together.
    pub members: Vec<usize>,
    /// Repairs per second the other links must deliver.
    pub required: f64,
}

#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub rates: Vec<f64>,
    /// Units that could not be fully protected (no diversity or capacity).
    pub unprotected: usize,
}

const EPS: f64 = 1e-9;
const TIE: f64 = 1e-6;

pub fn solve(links: &[PlanLink], units: &[Unit]) -> Plan {
    let n = links.len();
    let units: Vec<&Unit> = units.iter().filter(|u| u.required > 0.0).collect();
    if n == 0 || units.is_empty() {
        return Plan { rates: vec![0.0; n], unprotected: 0 };
    }
    let mut rates = vec![0.0; n];
    let mut unprotected = 0;
    for favoured in 0..n {
        let cost: Vec<f64> = links
            .iter()
            .enumerate()
            .map(|(j, l)| l.cost.max(1e-6) * if j == favoured { 1.0 - TIE } else { 1.0 })
            .collect();
        let plan = solve_with(links, &units, &cost);
        for (sum, rate) in rates.iter_mut().zip(&plan.rates) {
            *sum += rate / n as f64;
        }
        unprotected = unprotected.max(plan.unprotected);
    }
    Plan { rates, unprotected }
}

fn solve_with(links: &[PlanLink], units: &[&Unit], cost: &[f64]) -> Plan {
    let n = links.len();
    let m = units.len();
    let penalty = 1e6 * cost.iter().fold(1.0, |a, &b| f64::max(a, b));
    let units: Vec<&Unit> = units.to_vec();

    // Dual over w = (y_u per unit, z_j per link):
    //   maximize  sum_u required_u y_u - sum_j spare_j z_j
    //   subject to sum_{u: j not in u} success_j y_u - z_j <= cost_j   (row j)
    //              y_u <= penalty                                     (row n + u)
    // Shadow prices of rows j are the rates; of rows n + u, the deficits.
    let vars = m + n;
    let rows = n + m;
    let width = vars + rows + 1;
    let rhs = width - 1;
    let mut t = vec![vec![0.0; width]; rows];
    let mut obj = vec![0.0; width];
    for j in 0..n {
        for (u, unit) in units.iter().enumerate() {
            if !unit.members.contains(&j) {
                t[j][u] = links[j].success.clamp(0.0, 1.0);
            }
        }
        t[j][m + j] = -1.0;
        t[j][vars + j] = 1.0;
        t[j][rhs] = cost[j];
        obj[m + j] = links[j].spare.max(0.0);
    }
    for (u, unit) in units.iter().enumerate() {
        t[n + u][u] = 1.0;
        t[n + u][vars + n + u] = 1.0;
        t[n + u][rhs] = penalty;
        obj[u] = -unit.required;
    }
    let mut basis: Vec<usize> = (vars..vars + rows).collect();
    for _ in 0..10_000 {
        // Bland's rule: lowest index enters and leaves, which cannot cycle.
        let Some(col) = (0..rhs).find(|&c| obj[c] < -EPS) else {
            break;
        };
        let mut pivot: Option<(usize, f64)> = None;
        for (r, row) in t.iter().enumerate() {
            if row[col] > EPS {
                let ratio = row[rhs] / row[col];
                let better = match pivot {
                    None => true,
                    Some((p, best)) => ratio < best - EPS || (ratio <= best + EPS && basis[r] < basis[p]),
                };
                if better {
                    pivot = Some((r, ratio));
                }
            }
        }
        let Some((p, _)) = pivot else {
            break;
        };
        let scale = t[p][col];
        for v in &mut t[p] {
            *v /= scale;
        }
        let pivot_row = t[p].clone();
        for (r, row) in t.iter_mut().enumerate() {
            if r != p && row[col].abs() > EPS {
                let f = row[col];
                for (v, &pv) in row.iter_mut().zip(&pivot_row) {
                    *v -= f * pv;
                }
            }
        }
        let f = obj[col];
        for (v, &pv) in obj.iter_mut().zip(&pivot_row) {
            *v -= f * pv;
        }
        basis[p] = col;
    }
    let rates: Vec<f64> = (0..n)
        .map(|j| obj[vars + j].clamp(0.0, links[j].spare.max(0.0)))
        .collect();
    let unprotected = (0..m).filter(|&u| obj[vars + n + u] > 1e-6).count();
    Plan { rates, unprotected }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn equal(n: usize) -> Vec<PlanLink> {
        (0..n)
            .map(|_| PlanLink { success: 1.0, spare: 1_000.0, cost: 1.0 })
            .collect()
    }

    fn singles(n: usize, required: f64) -> Vec<Unit> {
        (0..n).map(|i| Unit { members: vec![i], required }).collect()
    }

    #[test]
    fn three_equal_links_need_half_the_stream_not_two_extra_copies() {
        // Stream of 300 packets/s, 100 per link.
        let plan = solve(&equal(3), &singles(3, 100.0));
        let total: f64 = plan.rates.iter().sum();
        assert_eq!(plan.unprotected, 0);
        assert!((total - 150.0).abs() < 5.0, "total repairs {total}");
    }

    #[test]
    fn equal_links_share_the_repairs_evenly() {
        let plan = solve(&equal(4), &singles(4, 100.0));
        let total: f64 = plan.rates.iter().sum();
        assert!((total - 400.0 / 3.0).abs() < 1e-6, "total {total}");
        for rate in &plan.rates {
            assert!((rate - total / 4.0).abs() < 1e-6, "rates {:?}", plan.rates);
        }
    }

    #[test]
    fn two_links_degenerate_to_duplication() {
        let plan = solve(&equal(2), &singles(2, 100.0));
        let total: f64 = plan.rates.iter().sum();
        assert!((total - 200.0).abs() < 5.0, "total repairs {total}");
    }

    #[test]
    fn unequal_shares_reach_the_true_minimum() {
        // One link carries 70% of the stream. Covering it needs 70 from the
        // other two, and that same 70 can already cover the small links.
        let units = [(0, 70.0), (1, 20.0), (2, 10.0)].map(|(i, r)| Unit { members: vec![i], required: r });
        let plan = solve(&equal(3), &units);
        let total: f64 = plan.rates.iter().sum();
        assert!((total - 70.0).abs() < 1e-6, "total repairs {total}");
        for u in &units {
            let covered: f64 = (0..3).filter(|j| !u.members.contains(j)).map(|j| plan.rates[j]).sum();
            assert!(covered >= u.required - 1e-6);
        }
    }

    #[test]
    fn an_impossible_unit_does_not_stop_the_others_being_protected() {
        let units = vec![
            Unit { members: vec![0, 1], required: 50.0 },
            Unit { members: vec![0], required: 30.0 },
        ];
        let plan = solve(&equal(2), &units);
        assert_eq!(plan.unprotected, 1);
        assert!((plan.rates[1] - 30.0).abs() < 1e-6 && plan.rates[0].abs() < 1e-6);
    }

    #[test]
    fn spare_capacity_caps_a_link_and_the_rest_moves_elsewhere() {
        let mut links = equal(3);
        links[1].spare = 10.0;
        let plan = solve(&links, &[Unit { members: vec![0], required: 40.0 }]);
        assert!(plan.rates[1] <= 10.0 + 1e-6);
        assert!((plan.rates[1] + plan.rates[2] - 40.0).abs() < 1e-6);
        assert_eq!(plan.unprotected, 0);
    }

    #[test]
    fn a_group_covering_every_link_cannot_be_protected() {
        let units = vec![Unit { members: vec![0, 1], required: 50.0 }];
        let plan = solve(&equal(2), &units);
        assert_eq!(plan.unprotected, 1);
        assert_eq!(plan.rates.iter().sum::<f64>(), 0.0);
    }

    #[test]
    fn metered_links_are_used_only_when_needed() {
        let mut links = equal(3);
        links[2].cost = 10.0;
        // Only link 0 can fail: links 1 and 2 could cover it; 1 is cheaper.
        let plan = solve(&links, &[Unit { members: vec![0], required: 80.0 }]);
        assert!(plan.rates[2] < 1e-9);
        assert!((plan.rates[1] - 80.0).abs() < 2.0);
    }
}
