#include "preload/virtualization_early_detector.h"

#include <mutex>
#include <sstream>

#include "virtualization/snapshot_builder.h"

namespace duckdetector::preload::virtualization {

    namespace {

        std::mutex g_mutex;
        EarlyVirtualizationResult g_result{};
        bool g_contextValid = false;

        void append_signal(EarlyVirtualizationResult &result, const char *label) {
            if (!result.detectionMethod.empty()) {
                result.detectionMethod += ", ";
            }
            result.detectionMethod += label;
        }

    }  // namespace

    EarlyVirtualizationResult run_early_detection() {
        std::lock_guard<std::mutex> lock(g_mutex);
        const auto snapshot = duckdetector::virtualization::collect_snapshot();

        EarlyVirtualizationResult result;
        result.hasRun = true;
        result.detected = false;
        result.details = "Startup virtualization preload completed without anomalies.";
        result.mountNamespaceInode = snapshot.mountNamespaceInode;
        result.apexMountKey = snapshot.apexMountKey;
        result.systemMountKey = snapshot.systemMountKey;
        result.vendorMountKey = snapshot.vendorMountKey;

        for (const auto &finding: snapshot.findings) {
            result.findings.push_back(
                    finding.label + "|" + finding.value + "|" + finding.severity
            );

            if (finding.label == "ro.kernel.qemu" || finding.label == "QEMU guest properties") {
                result.qemuPropertyDetected = true;
            }
            if (finding.label == "Emulator hardware props") {
                result.emulatorHardwareDetected = true;
            }
            if (finding.label == "Emulator device node") {
                result.deviceNodeDetected = true;
            }
            if (finding.label == "AVF runtime") {
                result.avfRuntimeDetected = true;
            }
            if (finding.label == "authfs runtime") {
                result.authfsRuntimeDetected = true;
            }
            if (finding.group == "TRANSLATION") {
                result.nativeBridgeDetected = true;
            }
        }

        if (result.qemuPropertyDetected) append_signal(result, "QEMU property");
        if (result.emulatorHardwareDetected) append_signal(result, "Emulator hardware");
        if (result.deviceNodeDetected) append_signal(result, "Device node");
        if (result.avfRuntimeDetected) append_signal(result, "AVF runtime");
        if (result.authfsRuntimeDetected) append_signal(result, "authfs runtime");
        if (result.nativeBridgeDetected) append_signal(result, "Native bridge");

        result.detected = result.qemuPropertyDetected ||
                          result.emulatorHardwareDetected ||
                          result.deviceNodeDetected ||
                          result.avfRuntimeDetected ||
                          result.authfsRuntimeDetected ||
                          result.nativeBridgeDetected;
        if (result.detected) {
            std::ostringstream detail;
            detail << "Startup preload captured ";
            detail << result.detectionMethod;
            result.details = detail.str();
        }

        g_result = result;
        g_contextValid = true;
        return g_result;
    }

    const EarlyVirtualizationResult *get_stored_result() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_result.hasRun ? &g_result : nullptr;
    }

    bool has_early_detection_run() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_result.hasRun;
    }

    bool is_preload_context_valid() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_contextValid;
    }

    void reset_early_detection() {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_result = EarlyVirtualizationResult{};
        g_contextValid = false;
    }

}  // namespace duckdetector::preload::virtualization
