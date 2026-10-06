# Minification is exercised in the release build; rules accumulate per
# dependency (JGit/SSHD, AIDL) as phases land.

# JGit references desktop-JVM classes in paths that never execute on
# Android (MBean monitoring, PID locks via ProcessHandle) and JSch
# references GSS-API (Kerberos transport). Neither is loaded on-device;
# silence the missing-class warnings R8 would otherwise fail on.
-dontwarn java.lang.ProcessHandle
-dontwarn java.lang.management.**
-dontwarn javax.management.**
-dontwarn org.ietf.jgss.**
