import SwiftUI
import Charts

private let mint = Color(red: 0.12, green: 0.91, blue: 0.72)
private let cyan = Color(red: 0.20, green: 0.76, blue: 0.98)
private let panel = Color(red: 0.075, green: 0.09, blue: 0.11)
private let muted = Color(red: 0.52, green: 0.58, blue: 0.63)

struct BrandMark: View {
    var body: some View {
        GeometryReader { geometry in
            Path { p in
                let scale = min(geometry.size.width, geometry.size.height) / 100
                p.move(to: CGPoint(x: 10 * scale, y: 14 * scale))
                p.addLine(to: CGPoint(x: 44 * scale, y: 86 * scale))
                p.addLine(to: CGPoint(x: 60 * scale, y: 14 * scale))
                p.addLine(to: CGPoint(x: 90 * scale, y: 14 * scale))
                p.addLine(to: CGPoint(x: 50 * scale, y: 86 * scale))
                p.addLine(to: CGPoint(x: 90 * scale, y: 86 * scale))
            }.stroke(LinearGradient(colors: [cyan, mint], startPoint: .topLeading, endPoint: .bottomTrailing),
                     style: StrokeStyle(lineWidth: geometry.size.width * 0.085, lineCap: .round, lineJoin: .round))
        }
    }
}

struct ContentView: View {
    @ObservedObject var model: LinkModel
    private let pages = [("Connection", "point.3.connected.trianglepath.dotted"), ("Diagnostics", "waveform.path.ecg"),
                         ("Activity", "text.alignleft"), ("Settings", "slider.horizontal.3")]
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 10) {
                    BrandMark().frame(width: 34, height: 34)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("VERZ").font(.system(size: 23, weight: .bold, design: .rounded)).tracking(3)
                        Text("LINK").font(.system(size: 10, weight: .semibold)).tracking(5).foregroundStyle(muted)
                    }
                }.padding(.bottom, 46).padding(.top, 30)
                Text("WORKSPACE").font(.system(size: 9, weight: .bold)).tracking(2).foregroundStyle(muted).padding(.bottom, 16)
                ForEach(pages, id: \.0) { page in
                    Button { model.selectedPage = page.0 } label: {
                        HStack(spacing: 12) {
                            Image(systemName: page.1).frame(width: 20)
                            Text(page.0).font(.system(size: 13, weight: model.selectedPage == page.0 ? .semibold : .medium))
                            Spacer()
                            if model.selectedPage == page.0 { Circle().fill(mint).frame(width: 5, height: 5) }
                        }.foregroundStyle(model.selectedPage == page.0 ? mint : muted)
                            .padding(.horizontal, 12).padding(.vertical, 13)
                            .background(model.selectedPage == page.0 ? mint.opacity(0.085) : .clear, in: RoundedRectangle(cornerRadius: 9))
                    }.buttonStyle(.plain).padding(.bottom, 5)
                }
                Spacer()
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 7) {
                        Circle().fill(model.state == .connected ? mint : muted).frame(width: 6, height: 6)
                        Text(model.state == .connected ? "RUST ENGINE ACTIVE" : "RUST ENGINE READY")
                            .font(.system(size: 9, weight: .bold)).tracking(0.8)
                    }.foregroundStyle(model.state == .connected ? mint : muted)
                    Text("Native macOS · v\(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "development")").font(.system(size: 11)).foregroundStyle(muted)
                    Text("Development build").font(.system(size: 10)).foregroundStyle(muted.opacity(0.65))
                }.padding(.bottom, 24)
            }.padding(.horizontal, 22).frame(width: 214)
                .background(Color(red: 0.035, green: 0.047, blue: 0.060))
            Rectangle().fill(.white.opacity(0.06)).frame(width: 1)
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    HStack {
                        VStack(alignment: .leading, spacing: 7) {
                            Text(model.selectedPage).font(.system(size: 28, weight: .semibold))
                            Text(subtitle).font(.system(size: 12)).foregroundStyle(muted)
                        }
                        Spacer()
                        Label(model.state == .connected ? model.mode.badge : "MAC CLIENT",
                              systemImage: model.mode == .secure ? "shield.lefthalf.filled" : "point.3.connected.trianglepath.dotted")
                            .font(.system(size: 9, weight: .bold)).tracking(1)
                            .foregroundStyle(model.state == .connected ? mint : muted)
                            .padding(10).background(panel, in: Capsule())
                    }.padding(.bottom, 4)
                    if let error = model.errorMessage {
                        HStack(alignment: .top) {
                            Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange)
                            Text(error).font(.system(size: 12)).textSelection(.enabled)
                            Spacer()
                            Button { model.errorMessage = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain)
                        }.padding(14).background(Color.orange.opacity(0.09), in: RoundedRectangle(cornerRadius: 10))
                    }
                    switch model.selectedPage {
                    case "Diagnostics": diagnostics
                    case "Activity": activity
                    case "Settings": settings
                    default: connection
                    }
                }.padding(30).padding(.top, 22)
            }.background(Color(red: 0.045, green: 0.057, blue: 0.072))
        }.tint(mint)
    }

    private var subtitle: String {
        switch model.selectedPage {
        case "Diagnostics": return "Measure the connection carrying your Mac’s traffic."
        case "Activity": return "A live record of your connection and test results."
        case "Settings": return "Choose direct acceleration or encrypted continuity."
        default: return model.mode == .secure ? "Your networks. One encrypted connection."
            : model.mode == .hybrid ? "Direct speed. Encrypted continuity when needed."
            : "Your networks. Direct, adaptive flow steering."
        }
    }

    private var connection: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 14) {
                eyebrow("CONNECTION MODE")
                Picker("Connection mode", selection: $model.mode) {
                    ForEach(TransportMode.allCases) { mode in Text(mode.title).tag(mode) }
                }.pickerStyle(.segmented).disabled(model.busy)
                Text(model.mode == .direct ? "No relay and no VERZ payload encryption. TCP connections are assigned directly across the selected adapters."
                     : model.mode == .hybrid ? "Direct-first flow steering with a warm encrypted relay. Secure-domain rules and failed direct connections escalate automatically."
                     : "Encrypted relay with a stable public IP and session-preserving path failover.")
                    .font(.system(size: 11)).foregroundStyle(muted)
            }.padding(18).card()
            VStack(alignment: .leading, spacing: 24) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 10) {
                        eyebrow("CONNECTION STATUS")
                        Text(model.state.rawValue).font(.system(size: 29, weight: .medium))
                        Text(model.state == .connected
                             ? (model.mode == .secure ? "Internet traffic uses the encrypted VERZ relay."
                                : model.mode == .hybrid ? "Direct and secure paths are active; the encrypted brain advises flow placement."
                                : "Supported TCP applications use direct flows across your enabled networks.")
                             : model.state == .reconnecting
                             ? (model.mode == .secure ? "Waiting for a usable path. Your secure tunnel stays in place." : "No direct path is healthy; adapters continue probing.")
                             : (model.mode == .secure ? "Connect Wi-Fi or Ethernet to Secure Continuity."
                                : model.mode == .hybrid ? "Connect Wi-Fi or Ethernet to start Automatic Hybrid."
                                : "Connect Wi-Fi or Ethernet to start Direct Smart."))
                            .font(.system(size: 12)).foregroundStyle(muted)
                    }
                    Spacer()
                    ZStack {
                        Circle().stroke(mint.opacity(0.12), lineWidth: 1).frame(width: 78, height: 78)
                        Circle().fill(mint.opacity(0.07)).frame(width: 60, height: 60)
                        Image(systemName: model.state == .connected ? (model.mode == .secure ? "lock.shield.fill" : "arrow.triangle.branch") : "power")
                            .font(.system(size: 24, weight: .light)).foregroundStyle(mint)
                    }
                }
                HStack(spacing: 18) {
                    Button { model.busy ? model.disconnect() : model.connect() } label: {
                        HStack(spacing: 10) {
                            if model.state == .authorizing || model.state == .connecting || model.state == .disconnecting {
                                ProgressView().controlSize(.small)
                            } else { Image(systemName: "power") }
                            Text(model.busy ? "Disconnect" : "Connect").fontWeight(.semibold)
                        }.frame(width: 150, height: 42)
                            .foregroundStyle(model.busy ? mint : Color.black)
                            .background(model.busy ? mint.opacity(0.12) : mint, in: RoundedRectangle(cornerRadius: 9))
                    }.buttonStyle(.plain).disabled(model.state == .disconnecting || (!model.busy && !model.hasReadyInterface))
                    Text(model.state == .connected ? "UPTIME  \(uptime)" : "One-time macOS helper setup · normal connections need no password")
                        .font(.system(size: 10, weight: .medium, design: .monospaced)).foregroundStyle(muted)
                    Spacer()
                }
                Divider().overlay(.white.opacity(0.03))
                HStack(spacing: 16) {
                    detail(model.mode == .secure ? "RELAY" : "DATA PATH",
                           model.mode == .secure ? model.relay : model.mode == .hybrid ? "Direct + selective relay" : "Direct to destination")
                    Spacer()
                    detail("PUBLIC IPv4", model.publicIP ?? (model.state == .connected ? "Verifying…" : "—"))
                    Spacer()
                    detail("PAYLOAD SECURITY", model.mode == .secure ? "VERZ + application"
                           : model.mode == .hybrid ? "Selective VERZ + application" : "Application-native")
                }
            }.padding(24).card()
            networkInterfaces
            HStack(spacing: 14) {
                metric("DOWNLOAD", String(format: "%.2f", model.receivedMbps), "Mbps", "arrow.down", cyan)
                metric("UPLOAD", String(format: "%.2f", model.sentMbps), "Mbps", "arrow.up", mint)
                metric("DATA TRANSFERRED", ByteCountFormatter.string(fromByteCount: Int64(model.receivedBytes + model.sentBytes), countStyle: .decimal), "this session", "arrow.up.arrow.down", muted)
            }
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    eyebrow("LIVE TRAFFIC")
                    Spacer()
                    Text("↓ Download").foregroundStyle(cyan)
                    Text("↑ Upload").foregroundStyle(mint)
                }.font(.system(size: 10))
                Chart(Array(model.samples.enumerated()), id: \.element.id) { index, sample in
                    LineMark(x: .value("Seconds", index), y: .value("Mbps", sample.received), series: .value("Direction", "Download")).foregroundStyle(cyan)
                    LineMark(x: .value("Seconds", index), y: .value("Mbps", sample.sent), series: .value("Direction", "Upload")).foregroundStyle(mint)
                }.chartXScale(domain: 0...59).chartXAxis(.hidden)
                    .chartYAxis { AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) }
                    .frame(height: 105)
                    .overlay { if model.samples.isEmpty { Text("Live measurements appear when connected").font(.system(size: 11)).foregroundStyle(muted) } }
                HStack {
                    Text(model.mode == .secure ? "Last 60 seconds · actual tunnel interface counters" : "Last 60 seconds · aggregate selected-adapter counters")
                    Spacer()
                    Text("Mbps")
                }.font(.system(size: 9)).foregroundStyle(muted)
            }.padding(20).card()
        }
    }

    private var networkInterfaces: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                eyebrow("YOUR NETWORK INTERFACES")
                Spacer()
                Text("Updates automatically").font(.system(size: 10)).foregroundStyle(muted)
                Button { model.refreshInterfaces() } label: { Image(systemName: "arrow.clockwise") }
                    .help("Refresh network interfaces")
            }
            if model.visibleInterfaces.isEmpty {
                Text("No connected networks. Join Wi-Fi or plug in an Ethernet cable.").font(.system(size: 12)).foregroundStyle(muted)
            }
            ForEach(model.visibleInterfaces) { interface in
                HStack(spacing: 12) {
                    Image(systemName: interface.isWiFi ? "wifi" : "cable.connector")
                        .font(.system(size: 17)).frame(width: 26)
                        .foregroundStyle(interface.canConnect ? mint : muted)
                    VStack(alignment: .leading, spacing: 5) {
                        Text(interface.title).font(.system(size: 12, weight: .medium))
                        Text([interface.status, interface.address ?? interface.addresses.first].compactMap { $0 }.joined(separator: " · "))
                            .font(.system(size: 10)).foregroundStyle(muted)
                    }
                    Spacer()
                    if let path = model.bondTelemetry?.paths.first(where: { $0.name == interface.name }), model.busy {
                        VStack(alignment: .trailing, spacing: 4) {
                            Text(path.state == "offline" ? "Offline" : path.uploadHeld == true
                                 ? "Upload congested · new flows prefer another link" : (path.latencyExcluded == true || path.realtimePreferred == false)
                                 ? "Transfers · calls prefer another link" : path.state.capitalized)
                                .foregroundStyle(path.state == "healthy" ? mint : muted)
                            Text(path.rttMs.map { String(format: "%.1f ms RTT", $0) } ?? "Measuring…").foregroundStyle(muted)
                            let rate = model.pathRates[path.name] ?? (upMbps: 0, downMbps: 0)
                            Text(String(format: "↑ %.2f  ↓ %.2f Mbps", rate.upMbps, rate.downMbps))
                                .font(.system(size: 12, weight: .semibold)).monospacedDigit()
                                .foregroundStyle(path.state == "healthy" ? Color.primary : muted)
                                .help("Live tunnel bytes carried on this link, including protection copies and repairs. Links can add up to more than the headline rate.")
                            if let down = path.downloadBps, let up = path.uploadBps {
                                Text(String(format: "↓ %.1f  ↑ %.1f Mbps · %llu flows", down / 1_000_000, up / 1_000_000, path.activeFlows ?? 0))
                                    .foregroundStyle(muted)
                                if path.tcpObserved == true {
                                    Text("Upload rate: TCP-acknowledged bytes").foregroundStyle(muted)
                                } else if path.tcpObserved == false {
                                    Text("Upload delivery: not measured yet").foregroundStyle(muted)
                                }
                            }
                        }.font(.system(size: 10))
                    }
                    if let udp = model.udpPaths[interface.name], model.busy {
                        VStack(alignment: .trailing, spacing: 4) {
                            Text(udp.healthy ? "UDP ready" : "UDP waiting").foregroundStyle(udp.healthy ? mint : muted)
                            Text(String(format: "%.1f ms RTT", udp.rtt))
                            Text(String(format: "↓ %.1f  ↑ %.1f Mbps", udp.downloadMbps, udp.uploadMbps))
                            Text("UDP carrier · includes copies")
                        }.font(.system(size: 10)).foregroundStyle(muted)
                    }
                    Toggle("Use", isOn: Binding(get: { !model.disabledInterfaces.contains(interface.name) },
                        set: { model.setInterface(interface.name, enabled: $0) })).toggleStyle(.switch).controlSize(.small)
                        .fixedSize()
                        .accessibilityIdentifier("interface-use-\(interface.name)")
                        .help("Include this adapter in the multipath connection")
                    Toggle("Metered", isOn: Binding(get: { model.meteredInterfaces.contains(interface.name) },
                        set: { model.setMetered(interface.name, metered: $0) })).controlSize(.small).fixedSize()
                        .accessibilityIdentifier("interface-metered-\(interface.name)")
                }.padding(.vertical, 5)
            }
            Text(model.mode == .secure
                 ? "Transfers can use all responsive links. Calls and recognized live streams prefer links below 75 ms RTT. Local congestion control protects the connection."
                 : model.mode == .hybrid
                 ? "The Mac measures TCP upload delivery and congestion. New connections use conservative two-way estimates; unknown or recovering links get limited trials. Existing direct flows stay on their original ISP."
                 : "Direct Smart shares new TCP flows using measured delivery and congestion. Unknown or recovering links get limited trials. One established direct connection stays on its original adapter.")
                .font(.system(size: 10)).foregroundStyle(muted)
            if model.busy && model.mode == .secure {
                Text("Per-link rates are live wire traffic on each adapter, including protection copies and repairs, so links can add up to more than the payload rate shown below.")
                    .font(.system(size: 10)).foregroundStyle(muted)
            }
            HStack {
                Text("Connection preference").font(.system(size: 12))
                Spacer()
                Picker("Connection preference", selection: $model.policy) {
                    Text("Bonding").tag("smart")
                    Text("Continuity").tag("continuity")
                    Text("Data saver").tag("data-saver")
                    // Legacy value: identical to Bonding for TCP; only spreads UDP flows.
                    if model.policy == "performance" { Text("Performance").tag("performance") }
                }.labelsHidden().frame(width: 160)
            }
            Text(model.policy == "continuity"
                 ? "Continuity: no drop during failover. Calls, UDP and TCP up to about 2 Mbps travel on two links at the same time; heavier transfers keep going on the surviving link and re-send only what was in flight. Session and public IP never change."
                 : model.policy == "data-saver"
                 ? "Data saver: uses unmetered links while they are healthy and never sends protection copies. A link failure is repaired, not masked."
                 : "Bonding: all links are combined for maximum throughput. Calls and live media still get a protection copy; other traffic is re-sent on the surviving link after a failure, which can pause briefly.")
                .font(.system(size: 10)).foregroundStyle(muted)
        }.padding(20).card()
    }

    private var diagnostics: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 7) {
                        Text("Test the real connection").font(.system(size: 20, weight: .semibold))
                        Text("10 ICMP pings, a file download, and a verified upload.").font(.system(size: 12)).foregroundStyle(muted)
                    }
                    Spacer()
                    Button("Run diagnostics") { model.runTest() }.buttonStyle(.borderedProminent).disabled(!model.canTest)
                }
                if model.testRunning {
                    ProgressView(value: model.testProgress)
                    Text(model.testStage).font(.system(size: 12)).foregroundStyle(mint)
                } else if model.mode == .direct {
                    Label("These relay diagnostics belong to Secure Continuity. Use a browser speed test for Direct Smart.", systemImage: "info.circle").font(.system(size: 12)).foregroundStyle(muted)
                } else if model.state != .connected {
                    Label("Connect with Secure Continuity before starting a relay test.", systemImage: "info.circle").font(.system(size: 12)).foregroundStyle(muted)
                } else if !model.testStage.isEmpty { Text(model.testStage).font(.system(size: 12)).foregroundStyle(mint) }
            }.padding(24).card()
            if let result = model.result {
                HStack {
                    eyebrow("LAST COMPLETED TEST")
                    Spacer()
                    Text(result.date.formatted()).font(.system(size: 11)).foregroundStyle(muted)
                }
                HStack(spacing: 14) {
                    metric("LATENCY · AVERAGE", String(format: "%.2f", result.averageMs), "ms", "waveform.path.ecg", mint)
                    metric("PING LOSS", String(format: "%.1f", result.lossPercent), "%", "circle.dotted", cyan)
                    metric("INTEGRITY", "Verified", "SHA-256 · both files", "checkmark.shield", mint)
                }
                VStack(alignment: .leading, spacing: 18) {
                    transfer("Download", bytes: result.downloadBytes, speed: result.downloadMbps, hash: result.downloadHash, symbol: "arrow.down")
                    Divider()
                    transfer("Upload", bytes: result.uploadBytes, speed: result.uploadMbps, hash: result.uploadHash, symbol: "arrow.up")
                    Text("These are short file-transfer measurements, not a sustained capacity or bonding benchmark.")
                        .font(.system(size: 11)).foregroundStyle(muted)
                }.padding(24).card()
                Button("Export test report…") { model.exportReport() }
            } else {
                VStack(spacing: 14) {
                    Image(systemName: "waveform.path.ecg").font(.system(size: 38, weight: .ultraLight)).foregroundStyle(mint)
                    Text("Your first measurement starts here").font(.system(size: 16))
                    Text("Results will be saved on this Mac. No generated numbers.").font(.system(size: 12)).foregroundStyle(muted)
                }.frame(maxWidth: .infinity).padding(.vertical, 70).card()
            }
            Label("100 ms maximum failover disruption is a release gate. Passing ping or file-transfer checks alone does not validate that gate.", systemImage: "hammer")
                .font(.system(size: 11)).foregroundStyle(muted)
        }
    }

    private var activity: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack { eyebrow("SESSION EVENTS"); Spacer(); Button("Export report…") { model.exportReport() } }
            VStack(alignment: .leading, spacing: 0) {
                ForEach(model.activity.reversed()) { item in
                    HStack(alignment: .top, spacing: 16) {
                        Text(item.date.formatted(date: .omitted, time: .standard)).foregroundStyle(muted).frame(width: 86, alignment: .leading)
                        Text(item.message).frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                    }.font(.system(size: 11, design: .monospaced)).padding(.vertical, 12)
                    Divider().opacity(0.3)
                }
            }.padding(20).card()
        }
    }

    private var settings: some View {
        VStack(alignment: .leading, spacing: 20) {
            VStack(alignment: .leading, spacing: 16) {
                eyebrow("ARCHITECTURE")
                settingRow("Selected mode", model.mode.title)
                settingRow("Data route", model.mode == .secure ? "Encrypted relay"
                           : model.mode == .hybrid ? "Direct with selective encrypted relay" : "Direct to destination")
                settingRow("VERZ payload encryption", model.mode == .secure ? "All payloads"
                           : model.mode == .hybrid ? "Escalated payloads only" : "None")
                Text("HTTPS, TLS, and other application encryption remain unchanged in every mode. The Direct Smart engine never decrypts or inspects payloads.")
                    .font(.system(size: 11)).foregroundStyle(muted)
            }.padding(24).card()
            if model.mode != .direct {
            VStack(alignment: .leading, spacing: 18) {
                eyebrow(model.mode == .hybrid ? "HYBRID SECURITY" : "SECURE CONTINUITY RELAY")
                if model.mode == .secure {
                    Text("Server address").font(.system(size: 13, weight: .medium))
                    TextField("IPv4:port", text: $model.relay).textFieldStyle(.roundedBorder).disabled(model.busy)
                    Text("Use the same relay profile on another Mac. Each connection receives its own encrypted session and private IPv4 address.")
                        .font(.system(size: 12)).foregroundStyle(muted)
                } else {
                    HStack {
                        Label(model.brainConnected ? "Encrypted brain connected" : "Local policy fallback",
                              systemImage: model.brainConnected ? "brain.head.profile.fill" : "brain.head.profile")
                            .foregroundStyle(model.brainConnected ? mint : muted)
                        Spacer()
                        Text(model.brainConnected ? "ADVICE #\(model.brainGeneration)" : "OFFLINE-SAFE")
                            .font(.system(size: 9, weight: .bold, design: .monospaced)).foregroundStyle(muted)
                    }.font(.system(size: 12))
                    Text("The encrypted brain learns from per-link TCP delivery, byte counts, timing and reachability. Unknown connections use conservative upload/download estimates, not a previous connection's direction. The Mac detects upload congestion locally and keeps its own controller during outages. No payloads or destinations are sent to the brain.")
                        .font(.system(size: 11)).foregroundStyle(muted)
                    if model.brainConnected {
                        Text(model.brainLearnedPaths == 0 ? "Learning from traffic as you use the connection…"
                             : "Transfer performance observed on \(model.brainLearnedPaths) links")
                            .font(.system(size: 11)).foregroundStyle(mint)
                    }
                    Divider()
                    Text("Always use Secure Continuity for these domains").font(.system(size: 13, weight: .medium))
                    TextEditor(text: $model.secureDomainsText)
                        .font(.system(size: 11, design: .monospaced))
                        .frame(height: 76).padding(6)
                        .background(.black.opacity(0.18), in: RoundedRectangle(cornerRadius: 7))
                        .disabled(model.busy)
                    Text("Add call and live-stream domains before starting them; encrypted traffic on port 443 cannot be identified reliably. Recognized RTMP/RTSP/SIP/TURN ports also use the warm relay. Continuity preference relays all new supported TCP flows. Direct sessions cannot migrate to a different public IP.")
                        .font(.system(size: 11)).foregroundStyle(muted)
                }
                Divider()
                HStack {
                    Label(model.hasCredential ? "Connection key installed" : "Connection key required", systemImage: model.hasCredential ? "checkmark.shield" : "key")
                        .foregroundStyle(model.hasCredential ? mint : .orange)
                    Spacer()
                    Button("Import profile or key…") { model.importKey() }.disabled(model.busy)
                }.font(.system(size: 12))
                Button("Export private profile for another Mac…") { model.exportProfile() }.disabled(!model.hasCredential)
                Text("The app never contains your key. Profiles include relay access credentials: transfer them privately. Credentials are stored in a permission-restricted file on this Mac.")
                    .font(.system(size: 11)).foregroundStyle(muted)
            }.padding(24).card()
            }
            VStack(alignment: .leading, spacing: 16) {
                eyebrow("THIS BUILD")
                settingRow("Networking engine", model.mode == .secure ? "Rust · native system tunnel"
                           : model.mode == .hybrid ? "Rust · direct + warm secure tunnel" : "Rust · local TCP flow engine")
                settingRow("Authentication", model.mode == .direct ? "Local signed helper" : "Noise PSK + ephemeral X25519")
                settingRow("Traffic", model.mode == .secure ? "IPv4 internet + DNS through relay"
                           : model.mode == .hybrid ? "Proxy-aware TCP direct or selectively relayed" : "Proxy-aware IPv4 TCP direct")
                settingRow("DNS", model.mode == .secure ? "Relay DNS while connected" : "Existing Mac DNS settings preserved")
                settingRow("IPv6", model.mode == .secure ? "Blocked by tunnel routes while connected" : "Direct support pending")
                settingRow("Local network", "Existing more-specific LAN routes remain local")
                settingRow("Uplinks", "Dynamic Wi-Fi and Ethernet paths")
                settingRow("Distribution", "Universal · macOS 14+ · development-signed")
                Divider()
                Text(model.mode == .secure
                     ? "Secure Continuity uses the current test relay. Production enrollment and audited release gates are not complete."
                     : model.mode == .hybrid
                     ? "Proxy-aware TCP is classified by Hybrid. Traffic that does not honor the system SOCKS proxy currently stays on the warm secure tunnel; transparent per-flow UDP/QUIC classification requires the Apple Network Extension production gate."
                     : "Direct Smart currently covers macOS applications that honor the system SOCKS proxy. Transparent UDP/QUIC and single-session migration require the Apple Network Extension production gate.")
                    .font(.system(size: 12)).foregroundStyle(muted)
            }.padding(24).card()
        }
    }

    private var uptime: String { String(format: "%02d:%02d:%02d", model.uptime / 3600, model.uptime / 60 % 60, model.uptime % 60) }
    private func eyebrow(_ text: String) -> some View { Text(text).font(.system(size: 9, weight: .bold)).tracking(1.5).foregroundStyle(muted) }
    private func detail(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 8) { eyebrow(title); Text(value).font(.system(size: 11, weight: .medium, design: .monospaced)).textSelection(.enabled) }
    }
    private func metric(_ title: String, _ value: String, _ unit: String, _ icon: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 15) {
            HStack { eyebrow(title); Spacer(); Image(systemName: icon).foregroundStyle(color).font(.system(size: 11)) }
            Text(value).font(.system(size: 25, weight: .medium, design: .rounded)).lineLimit(1).minimumScaleFactor(0.6)
            Text(unit).font(.system(size: 10)).foregroundStyle(muted)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(18).card()
    }
    private func settingRow(_ label: String, _ value: String) -> some View {
        HStack { Text(label).foregroundStyle(muted); Spacer(); Text(value) }.font(.system(size: 12))
    }
    private func transfer(_ title: String, bytes: Int, speed: Double, hash: String, symbol: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack { Label(title, systemImage: symbol).foregroundStyle(mint); Spacer(); Text(String(format: "%.2f Mbps", speed)).fontWeight(.semibold) }
            Text("\(ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)) · SHA-256 verified").font(.system(size: 11)).foregroundStyle(muted)
            Text(hash).font(.system(size: 9, design: .monospaced)).foregroundStyle(muted).textSelection(.enabled)
        }
    }
}

private extension View {
    func card() -> some View {
        background(panel, in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(.white.opacity(0.055), lineWidth: 1))
    }
}
