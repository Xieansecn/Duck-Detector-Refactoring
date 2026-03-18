package com.eltavine.duckdetector.core.packagevisibility

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

enum class InstalledPackageVisibility {
    UNKNOWN,
    FULL,
    RESTRICTED,
}

object InstalledPackageVisibilityChecker {

    fun detect(
        context: Context,
        installedPackageCount: Int,
    ): InstalledPackageVisibility {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            return InstalledPackageVisibility.FULL
        }
        return if (installedPackageCount > 10) {
            InstalledPackageVisibility.FULL
        } else {
            InstalledPackageVisibility.RESTRICTED
        }
    }

    @Suppress("DEPRECATION")
    fun getInstalledPackages(context: Context): Set<String> {
        return runCatching {
            val applications = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getInstalledApplications(
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong()),
                )
            } else {
                context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
            }
            applications.mapTo(linkedSetOf()) { it.packageName }
        }.getOrDefault(emptySet())
    }
}
