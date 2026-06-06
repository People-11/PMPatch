package com.v7878.hooks.pmpatch;

import static com.v7878.hooks.pmpatch.Main.TAG;
import static com.v7878.unsafe.Reflection.getHiddenExecutables;

import android.util.Log;

import com.v7878.vmtools.HookTransformer;
import com.v7878.vmtools.Hooks;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class BulkHooker {
    public record HookElement(HookTransformer impl, Pattern pattern) {
    }

    private final Map<String, List<HookElement>> hooks = new HashMap<>();

    public void addPattern(HookTransformer impl, String clazz, String pattern) {
        hooks.computeIfAbsent(clazz, unused -> new ArrayList<>())
                .add(new HookElement(impl, Pattern.compile(pattern)));
    }

    public void addAll(HookTransformer impl, String clazz, String method_name) {
        addPattern(impl, clazz, String.format("%s\\(.*\\).*", Pattern.quote(method_name)));
    }

    public void addExact(HookTransformer impl, String clazz, String method_name, String ret, String... args) {
        addPattern(impl, clazz, String.format("%s\\(%s\\)%s", Pattern.quote(method_name),
                Pattern.quote(String.join(", ", args)), Pattern.quote(ret)));
    }

    public void apply(ClassLoader loader) {
        for (var entry : hooks.entrySet()) {
            Class<?> clazz;
            try {
                clazz = Class.forName(entry.getKey(), true, loader);
            } catch (ClassNotFoundException ex) {
                Log.e(TAG, String.format("Class %s not found", entry.getKey()));
                continue;
            }
            var executables = getHiddenExecutables(clazz);
            var elements = entry.getValue();
            for (var executable : executables) {
                var descriptor = Utils.printExecutable(executable);
                for (var element : elements) {
                    if (element.pattern().matcher(descriptor).matches()) {
                        if (BuildConfig.DEBUG) {
                            Log.i(TAG, "Hooked: " + executable);
                        }
                        Hooks.hook(executable, Hooks.EntryPointType.DIRECT,
                                element.impl(), Hooks.EntryPointType.DIRECT);
                    }
                }
            }
        }
    }
}
