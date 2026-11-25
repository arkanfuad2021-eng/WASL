# SQLCipher rules
-keep class net.sqlcipher.** { *; }
-keep class net.sqlcipher.database.** { *; }

# Room database & generated _Impl protection under R8 full mode
-keep class * extends androidx.room.RoomDatabase {
    public <init>();
}
-keep class com.wasl.secure.data.local.WaslDatabase_Impl { *; }

# Preserve Enums serialized as names in Room & SharedPreferences (e.g. KEY_CHANGED_ALERT, MigrationState)
-keep enum com.wasl.secure.** { *; }

# Bouncy Castle rules
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
