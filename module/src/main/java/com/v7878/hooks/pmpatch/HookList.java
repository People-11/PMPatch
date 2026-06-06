package com.v7878.hooks.pmpatch;

import static android.content.pm.PackageManager.SIGNATURE_MATCH;
import static android.os.Build.VERSION.SDK_INT;
import static com.v7878.unsafe.access.AccessLinker.FieldAccessKind.INSTANCE_GETTER;
import static com.v7878.unsafe.invoke.EmulatedStackFrame.RETURN_VALUE_IDX;

import com.v7878.r8.annotations.DoNotOptimize;
import com.v7878.r8.annotations.DoNotShrinkType;
import com.v7878.unsafe.access.AccessLinker;
import com.v7878.unsafe.access.AccessLinker.FieldAccess;
import com.v7878.unsafe.invoke.Transformers;
import com.v7878.vmtools.HookTransformer;
import com.v7878.zygisk.ZygoteLoader;

import java.security.Signature;
import java.util.Arrays;

public class HookList {
    private static final int CERT_CAPABILITY_PERMISSION = 4;
    private static final int CERT_CAPABILITY_AUTH = 16;
    private static final int[] CERT_CAPABILITY_EXCLUDED = {
            CERT_CAPABILITY_PERMISSION,
            CERT_CAPABILITY_AUTH
    };

    private static final String[] PM_INSTALL_STACK = {
            "collectCertificates",
            "assertApkConsistent",
            "assertPackageConsistent",
            "installPackage",
            "preparePackage",
            "prepareScannedPackage",
            "parseVerityDigest",
            "reconcilePackage",
            "scanPackage",
            "scanDir",
            "validateApkInstall",
            "commitPackage",
            "replacePackage",
            "verifyIntegrity",
            "verifySigner",
            "verifyV"
    };

    private static boolean booleanProperty(String name) {
        if (BuildConfig.USE_CONFIG) {
            return Boolean.parseBoolean(ZygoteLoader.getProperties()
                    .getOrDefault(name, "true"));
        }
        return true;
    }

    @DoNotShrinkType
    @DoNotOptimize
    private abstract static class AccessI {
        @FieldAccess(kind = INSTANCE_GETTER, klass = "java.security.Signature", name = "state")
        abstract int state(Signature instance);

        static final AccessI INSTANCE = AccessLinker.generateImpl(AccessI.class);
    }

    private static void addSignatureVerifyHooks(BulkHooker hooks) {
        HookTransformer verify_impl = (original, frame) -> {
            HTF.printStackTrace(frame);
            var accessor = frame.accessor();

            Signature thiz = accessor.getReference(0);
            if (isPatchedSignatureAlgorithm(thiz.getAlgorithm())) {
                int state = AccessI.INSTANCE.state(thiz);
                if (state == 3 /* Signature.VERIFY */) {
                    frame.accessor().setBoolean(RETURN_VALUE_IDX, true);
                    return;
                }
            }

            Transformers.invokeExact(original, frame);
        };

        hooks.addExact(verify_impl, "java.security.Signature", "verify", "boolean", "byte[]");
        hooks.addExact(verify_impl, "java.security.Signature", "verify", "boolean", "byte[]", "int", "int");

        hooks.addExact(HTF.TRUE, "com.android.org.conscrypt.OpenSSLSignature", "engineVerify", "boolean", "byte[]");
    }

    private static boolean isPatchedSignatureAlgorithm(String algorithm) {
        return "rsa-sha1".equalsIgnoreCase(algorithm) ||
                "sha1withrsa".equalsIgnoreCase(algorithm) ||
                "sha256withdsa".equalsIgnoreCase(algorithm) ||
                "sha256withrsa".equalsIgnoreCase(algorithm);
    }

    private static void addDigestCompareHooks(BulkHooker hooks) {
        hooks.addExact(HTF.TRUE, "java.security.MessageDigest", "isEqual", "boolean", "byte[]", "byte[]");
    }

    public static void initCommon(BulkHooker hooks) {
        if (BuildConfig.PATCH_1 && booleanProperty("PATCH_1")) {
            addSignatureVerifyHooks(hooks);
        }

        if (BuildConfig.PATCH_2 && booleanProperty("PATCH_2")) {
            addDigestCompareHooks(hooks);
        }
    }

    public static void initSystem(BulkHooker hooks) {
        if (BuildConfig.PATCH_3 && booleanProperty("PATCH_3")) {
            var install_true = HTF.constantByStackPrefix(true, PM_INSTALL_STACK, null);
            var install_false = HTF.constantByStackPrefix(false, PM_INSTALL_STACK, null);
            var install_nop = HTF.constantByStackPrefix(null, PM_INSTALL_STACK, null);
            var install_signature_capability = HTF.constantByStackPrefixExceptIntArg(
                    true, 2, CERT_CAPABILITY_EXCLUDED, PM_INSTALL_STACK, null);

            {
                if (SDK_INT >= 28) {
                    // 28 - >>
                    hooks.addAll(install_signature_capability, "android.content.pm.PackageParser$SigningDetails", "checkCapability");
                    hooks.addAll(install_signature_capability, "android.content.pm.PackageParser$SigningDetails", "checkCapabilityRecover");
                    hooks.addAll(install_true, "android.content.pm.PackageParser$SigningDetails", "hasCommonAncestor");
                    hooks.addAll(install_true, "android.content.pm.PackageParser$SigningDetails", "signaturesMatchExactly");
                }
                if (SDK_INT >= 33) {
                    // 33 - >>
                    hooks.addAll(install_signature_capability, "android.content.pm.SigningDetails", "checkCapability");
                    hooks.addAll(install_signature_capability, "android.content.pm.SigningDetails", "checkCapabilityRecover");
                    hooks.addAll(install_true, "android.content.pm.SigningDetails", "hasCommonAncestor");
                    hooks.addAll(install_true, "android.content.pm.SigningDetails", "signaturesMatchExactly");
                }
            }

            if (SDK_INT < 33) {
                HookTransformer compare = HTF.constantByStackPrefix(SIGNATURE_MATCH, PM_INSTALL_STACK, null);
                if (SDK_INT <= 27) {
                    // 26 - 27
                    hooks.addExact(compare, "com.android.server.pm.PackageManagerService", "compareSignatures", "int", "android.content.pm.Signature[]", "android.content.pm.Signature[]");
                } else {
                    // 28 - >>
                    hooks.addExact(compare, "com.android.server.pm.PackageManagerServiceUtils", "compareSignatures", "int", "android.content.pm.Signature[]", "android.content.pm.Signature[]");
                }
                hooks.addAll(install_true, "android.content.pm.Signature", "areExactMatch");
            }

            if (SDK_INT <= 27) {
                // 26 - 27
                hooks.addAll(install_nop, "com.android.server.pm.PackageManagerService", "verifySignaturesLP");
            } else {
                // 28 - >>
                hooks.addAll(install_false, "com.android.server.pm.PackageManagerServiceUtils", "verifySignatures");
                hooks.addAll(install_false, "com.android.server.pm.PackageManagerServiceUtils", "matchSignatureInSystem");
                hooks.addAll(install_false, "com.android.server.pm.PackageManagerServiceUtils", "matchSignaturesCompat");
                hooks.addAll(install_false, "com.android.server.pm.PackageManagerServiceUtils", "matchSignaturesRecover");
            }

            if (SDK_INT == 31 || SDK_INT == 32) {
                // 31 - 32
                hooks.addAll(install_true, "com.android.server.pm.PackageManagerService", "doesSignatureMatchForPermissions");
            } else if (SDK_INT >= 33) {
                // 33 - >>
                hooks.addAll(install_true, "com.android.server.pm.InstallPackageHelper", "doesSignatureMatchForPermissions");
            }

            if (SDK_INT <= 32) {
                // 26 - 32
                hooks.addAll(HTF.NOP, "com.android.server.pm.PackageManagerService", "checkDowngrade");
                // 26 - 32
                //hooks.addAll(HTF.NOP, "com.android.server.pm.PackageManagerService", "assertPackageIsValid");
            } else {
                // 33 - >>
                hooks.addAll(HTF.NOP, "com.android.server.pm.PackageManagerServiceUtils", "checkDowngrade");
                // 33 - >>
                //hooks.addAll(HTF.NOP, "com.android.server.pm.InstallPackageHelper", "assertPackageIsValid");
            }

            if (SDK_INT >= 33) {
                // 33 - >>
                hooks.addAll(install_nop, "com.android.server.pm.ScanPackageUtils", "assertMinSignatureSchemeIsValid");
            }
            if (SDK_INT >= 30) {
                // 30 - >>
                hooks.addAll(HTF.constantByStackPrefix(1, PM_INSTALL_STACK, null), "android.util.apk.ApkSignatureVerifier", "getMinimumSignatureSchemeVersionForTargetSdk");
                // 30 - >>
                hooks.addAll(HTF.constantByStackPrefix(1, PM_INSTALL_STACK, null), "com.android.apksig.ApkVerifier", "getMinimumSignatureSchemeVersionForTargetSdk");
            }
            if (SDK_INT >= 28) {
                // Framework/APEX verifier paths used while parsing staged APKs in system_server.
                HookTransformer verity_digest = (original, frame) -> {
                    HTF.printStackTrace(frame);
                    byte[] data = frame.accessor().getReference(0);
                    frame.accessor().setValue(RETURN_VALUE_IDX, Arrays.copyOfRange(data, 0, 32));
                };

                hooks.addAll(install_nop, "android.util.apk.ApkSigningBlockUtils", "verifyIntegrityFor1MbChunkBasedAlgorithm");
                hooks.addAll(install_nop, "android.util.apk.ApkSigningBlockUtils", "verifyIntegrityForVerityBasedAlgorithm");
                hooks.addAll(verity_digest, "android.util.apk.ApkSigningBlockUtils", "parseVerityDigestAndVerifySourceLength");
                hooks.addPattern(install_true, "android.util.jar.StrictJarVerifier", ".*verifyMessageDigest\\(.*\\).*");
                hooks.addAll(install_true, "android.util.jar.StrictJarVerifier", "verify");
                hooks.addExact(install_true, "java.security.MessageDigest", "isEqual", "boolean", "byte[]", "byte[]");
                hooks.addExact(install_true, "com.android.org.conscrypt.OpenSSLSignature", "engineVerify", "boolean", "byte[]");
            }
            if (SDK_INT >= 30) {
                // Avoid install-time rejection for compressed or misaligned resources.arsc.
                hooks.addAll(install_false, "android.content.res.AssetManager", "containsAllocatedTable");
            }

            if (SDK_INT >= 31) {
                // 31 - >>
                hooks.addAll(install_true, "com.android.server.pm.KeySetManagerService", "checkUpgradeKeySetLocked");
                hooks.addAll(install_false, "com.android.server.pm.VerifyingSession", "isVerificationEnabled");
            }

            switch (SDK_INT) {
                case 26, 27, 28, 29, 30 -> // 26 - 30
                        hooks.addAll(HTF.TRUE, "com.android.server.pm.permission.PermissionManagerService", "hasPrivappWhitelistEntry");
                case 31, 32 -> // 31 - 32
                        hooks.addAll(HTF.TRUE, "com.android.server.pm.permission.PermissionManagerService", "isInSystemConfigPrivAppDenyPermissions");
                case 33 -> // 33
                        hooks.addAll(HTF.TRUE, "com.android.server.pm.permission.PermissionManagerServiceImpl", "isInSystemConfigPrivAppDenyPermissions");
                default -> // 34 - >>
                        hooks.addAll(HTF.TRUE, "com.android.server.pm.permission.PermissionManagerServiceImpl", "getPrivilegedPermissionAllowlistState");
            }
        }
    }

    public static void initApplication(String package_name, BulkHooker hooks) {
    }
}
