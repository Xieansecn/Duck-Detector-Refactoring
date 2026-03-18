#pragma once

#include <string>
#include <vector>

namespace duckdetector::virtualization {

    struct SnapshotFinding {
        std::string group;
        std::string severity;
        std::string label;
        std::string value;
        std::string detail;
    };

    struct Snapshot {
        bool available = false;
        bool eglAvailable = false;
        std::string eglVendor;
        std::string eglRenderer;
        std::string eglVersion;
        std::string mountNamespaceInode;
        std::string apexMountKey;
        std::string systemMountKey;
        std::string vendorMountKey;
        int mapLineCount = 0;
        int fdCount = 0;
        int mountInfoCount = 0;
        int environmentHitCount = 0;
        int translationHitCount = 0;
        int runtimeArtifactHitCount = 0;
        std::vector<SnapshotFinding> findings;
    };

    Snapshot collect_snapshot();

    std::string encode_snapshot(const Snapshot &snapshot);

}  // namespace duckdetector::virtualization
