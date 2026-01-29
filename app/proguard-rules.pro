# Slipstream VPN ProGuard Rules

# Keep JNI methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep NativeBridge class and its JNI callback methods
-keep class com.slipstream.vpn.data.native.NativeBridge {
    *;
}
-keep class com.slipstream.vpn.data.native.NativeCallback {
    *;
}
-keep class com.slipstream.vpn.data.native.NativeConfig {
    *;
}
-keep class com.slipstream.vpn.data.native.NativeStats {
    *;
}

# Hilt
-keep class dagger.hilt.** { *; }
-keep class javax.inject.** { *; }
-keep class * extends dagger.hilt.android.lifecycle.HiltViewModel { *; }

# Room
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-dontwarn androidx.room.paging.**

# DataStore
-keep class androidx.datastore.** { *; }

# Kotlin Serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

# Gson
-keepattributes Signature
-keepattributes *Annotation*
-dontwarn sun.misc.**
-keep class com.google.gson.** { *; }
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# Keep domain models for Gson serialization
-keep class com.slipstream.vpn.domain.model.** { *; }
-keep class com.slipstream.vpn.data.local.database.** { *; }

# Compose
-dontwarn androidx.compose.**
