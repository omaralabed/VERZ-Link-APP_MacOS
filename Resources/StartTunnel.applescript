on run argv
    set runDir to item 1 of argv
    set ownerUID to item 2 of argv
    set relay to item 3 of argv
    set linkInterface to item 4 of argv
    set linkPolicy to item 5 of argv
    set helperPath to quoted form of (runDir & "/verz-app-helper")
    set commandText to helperPath & " " & quoted form of runDir & " " & quoted form of ownerUID & " " & quoted form of relay & " " & quoted form of linkInterface & " " & quoted form of linkPolicy
    with timeout of 2147483 seconds
        return do shell script commandText with administrator privileges
    end timeout
end run
