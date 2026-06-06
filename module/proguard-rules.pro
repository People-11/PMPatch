# minSdk 26 (Android 8+) runs ART, not Dalvik — all optimizations are safe.
-optimizationpasses 10
-allowaccessmodification
-mergeinterfacesaggressively

-dontusemixedcaseclassnames
-verbose

-keepattributes *Annotation*

# For enumeration classes, see http://proguard.sourceforge.net/manual/examples.html#enumerations
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

-renamesourcefileattribute SourceFile
-keepattributes SourceFile,LineNumberTable

-dontobfuscate