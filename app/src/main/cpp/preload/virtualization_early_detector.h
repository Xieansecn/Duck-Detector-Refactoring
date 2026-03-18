#pragma once

#include <string>
#include <vector>

namespace duckdetector::preload::virtualization {

    struct EarlyVirtualizationResult {
        bool hasRun = false;
        bool detected = false;
        bool qemuPropertyDetected = false;
        bool emulatorHardwareDetected = false;
        bool deviceNodeDetected = false;
        bool avfRuntimeDetected = false;
        bool authfsRuntimeDetected = false;
        bool nativeBridgeDetected = false;
        std::string mountNamespaceInode;
        std::string apexMountKey;
        std::string systemMountKey;
        std::string vendorMountKey;
        std::string detectionMethod;
        std::string details;
        std::vector<std::string> findings;
    };

    EarlyVirtualizationResult run_early_detection();

    const EarlyVirtualizationResult *get_stored_result();

    bool has_early_detection_run();

    bool is_preload_context_valid();

    void reset_early_detection();

}  // namespace duckdetector::preload::virtualization
