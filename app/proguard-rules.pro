# SQLCipher rules
-keep class net.sqlcipher.** { *; }
-keep class net.sqlcipher.database.** { *; }

# Bouncy Castle rules
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Tink rules
-keep class com.google.crypto.tink.** { *; }
