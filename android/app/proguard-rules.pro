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

# JGit instantiates its translation bundle REFLECTIVELY
# (TranslationBundle.load -> getDeclaredConstructor().newInstance()); R8
# stripped the no-arg constructor and the minified build crashed with
# NoSuchMethodException at the first git clone (r2.a == JGitText).
-keep class org.eclipse.jgit.internal.JGitText { *; }

# JSch loads its cipher/MAC/compression/keyexchange implementations by
# name from its config (Class.forName + newInstance) — the SSH handshake
# would crash the same way on a minified build.
-keep class com.jcraft.jsch.** { *; }
-dontwarn com.jcraft.jsch.**

# BouncyCastle (bcpg/bcprov): the card-crypto path uses the lightweight
# (Bc*) operators — direct calls, no keeps needed. The jars reference
# optional JDK classes; silence them. The bcpg 1.79 jars ship NO consumer
# rules, and the OpenPGP framing (the SEIPD CFB, the MDC, the PKESKs) is
# load-bearing for the vault's hot path — re-verify the decrypt on a
# minified build if the BC version changes.
-dontwarn org.bouncycastle.**
