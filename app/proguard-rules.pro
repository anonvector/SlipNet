# SlipNet VPN ProGuard Rules

# Keep JNI methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep NativeBridge class and its JNI callback methods
-keep class app.slipnet.data.native.NativeBridge { *; }
-keep class app.slipnet.data.native.NativeCallback { *; }
-keep class app.slipnet.data.native.NativeConfig { *; }
-keep class app.slipnet.data.native.NativeStats { *; }

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

# Gson - preserve generic type information for TypeToken
-keepattributes Signature
-keepattributes *Annotation*
-keepattributes EnclosingMethod
-dontwarn sun.misc.**
-keep class com.google.gson.** { *; }
-keep class com.google.gson.reflect.TypeToken { *; }
-keep class * extends com.google.gson.reflect.TypeToken
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# Keep domain models for Gson serialization
-keep class app.slipnet.domain.model.** { *; }
-keep class app.slipnet.data.local.database.** { *; }
-keep class app.slipnet.data.mapper.** { *; }

# Compose
-dontwarn androidx.compose.**
