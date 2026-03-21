#!/usr/bin/swift
// AutoMunki postflight — built via `make` in agent/ → build/postflight (universal binary).
// POSTs JSON to /api/v1/reports/checkin. Deploy next to
// managedsoftwareupdate as executable "postflight":
// https://github.com/munki/munki/wiki/Preflight-And-Postflight-Scripts

import Darwin
import Foundation
import IOKit

private let managedInstallsDir = "/Library/Managed Installs"
private let managedInstallReportPath = "\(managedInstallsDir)/ManagedInstallReport.plist"
private let applicationInventoryPath = "\(managedInstallsDir)/ApplicationInventory.plist"
private let munkiVersionPlistPath = "/usr/local/munki/munkilib/version.plist"
private let managedInstallsPrefsDomain = "ManagedInstalls" as CFString

private func logErr(_ msg: String) {
  fputs("\(msg)\n", stderr)
}

private func sysctlString(_ name: String) -> String? {
  var size = 0
  sysctlbyname(name, nil, &size, nil, 0)
  guard size > 0 else { return nil }
  var buf = [CChar](repeating: 0, count: size)
  guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return nil }
  return String(cString: buf)
}

private func cpuBrandString() -> String {
  var size = 0
  sysctlbyname("machdep.cpu.brand_string", nil, &size, nil, 0)
  guard size > 0 else { return "" }
  var buf = [CChar](repeating: 0, count: size)
  sysctlbyname("machdep.cpu.brand_string", &buf, &size, nil, 0)
  return String(cString: buf)
}

private func serialNumber() -> String {
  let master: mach_port_t
  if #available(macOS 12.0, *) {
    master = kIOMainPortDefault
  } else {
    master = kIOMasterPortDefault
  }
  let platformExpert = IOServiceGetMatchingService(master, IOServiceMatching("IOPlatformExpertDevice"))
  guard platformExpert > 0 else { return "UNKNOWN" }
  defer { IOObjectRelease(platformExpert) }
  guard
    let serial = IORegistryEntryCreateCFProperty(
      platformExpert, "IOPlatformSerialNumber" as CFString, kCFAllocatorDefault, 0
    )?.takeRetainedValue() as? String
  else {
    return "UNKNOWN"
  }
  return serial
}

private func cfPrefString(_ key: CFString) -> String? {
  CFPreferencesCopyAppValue(key, managedInstallsPrefsDomain) as? String
}

/// Same origin as Munki’s repo URL (scheme + host + port). Check-in uses `/api/v1/...` on that host (Next.js proxy pattern).
private func apiBaseOrigin(fromSoftwareRepoURL raw: String) -> String? {
  let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
  guard !trimmed.isEmpty else { return nil }

  let withScheme: String
  if trimmed.lowercased().hasPrefix("http://") || trimmed.lowercased().hasPrefix("https://") {
    withScheme = trimmed
  } else {
    withScheme = "https://\(trimmed)"
  }

  guard let url = URL(string: withScheme),
    var comp = URLComponents(url: url, resolvingAgainstBaseURL: false),
    let scheme = comp.scheme, !scheme.isEmpty,
    let host = comp.host, !host.isEmpty
  else {
    return nil
  }
  // Ensure file:// and other non-network schemes are rejected (host required).
  guard scheme == "http" || scheme == "https" else { return nil }

  comp.path = ""
  comp.query = nil
  comp.fragment = nil
  comp.user = nil
  comp.password = nil
  guard let origin = comp.string else { return nil }
  return origin
}

private func diskStats() -> (totalGB: Int?, freeGB: Int?) {
  let url = URL(fileURLWithPath: "/")
  guard
    let vals = try? url.resourceValues(forKeys: [
      .volumeTotalCapacityKey,
      .volumeAvailableCapacityKey,
    ]),
    let total = vals.volumeTotalCapacity,
    let free = vals.volumeAvailableCapacity
  else {
    return (nil, nil)
  }
  return (total / 1_000_000_000, free / 1_000_000_000)
}

private func sysctlInt32(_ name: String) -> Int32? {
  var value: Int32 = 0
  var size = MemoryLayout<Int32>.size
  guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
  return value
}

private func cpuArchString() -> String {
  var arm: Int32 = 0
  var sz = MemoryLayout<Int32>.size
  if sysctlbyname("hw.optional.arm64", &arm, &sz, nil, 0) == 0, arm != 0 {
    return "arm64"
  }
  return "x86_64"
}

private func swVersBuildVersion() -> String {
  let p = Process()
  p.executableURL = URL(fileURLWithPath: "/usr/bin/sw_vers")
  p.arguments = ["-buildVersion"]
  let outPipe = Pipe()
  p.standardOutput = outPipe
  p.standardError = Pipe()
  do {
    try p.run()
    p.waitUntilExit()
    let data = outPipe.fileHandleForReading.readDataToEndOfFile()
    return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
  } catch {
    return ""
  }
}

private func platformUUIDString() -> String? {
  let master: mach_port_t
  if #available(macOS 12.0, *) {
    master = kIOMainPortDefault
  } else {
    master = kIOMasterPortDefault
  }
  let platformExpert = IOServiceGetMatchingService(master, IOServiceMatching("IOPlatformExpertDevice"))
  guard platformExpert > 0 else { return nil }
  defer { IOObjectRelease(platformExpert) }
  guard
    let uuid = IORegistryEntryCreateCFProperty(
      platformExpert, "IOPlatformUUID" as CFString, kCFAllocatorDefault, 0
    )?.takeRetainedValue() as? String
  else {
    return nil
  }
  let t = uuid.trimmingCharacters(in: .whitespacesAndNewlines)
  return t.isEmpty ? nil : t
}

/// First segment for Apple FMIP ``deviceImages-9.0`` URLs (same rules as MunkiReport).
private func appleImageFamily(productName: String, machineModel: String) -> String {
  let mm = machineModel.trimmingCharacters(in: .whitespacesAndNewlines)
  if mm == "iMacPro1,1" {
    return "iMac"
  }
  let compact = productName.replacingOccurrences(of: " ", with: "")
  if !compact.isEmpty {
    return compact
  }
  if let idx = mm.firstIndex(where: { $0.isNumber }) {
    let prefix = String(mm[..<idx])
    if !prefix.isEmpty {
      return prefix
    }
  }
  return mm.replacingOccurrences(of: " ", with: "")
}

private func iso8601(_ date: Date) -> String {
  let f = ISO8601DateFormatter()
  f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
  return f.string(from: date)
}

private func jsonSafeTime(_ value: Any?) -> String? {
  if let d = value as? Date {
    return iso8601(d)
  }
  if let s = value as? String, !s.isEmpty {
    return s
  }
  return nil
}

private func loadPlistDict(path: String) -> [String: Any]? {
  let url = URL(fileURLWithPath: path)
  guard let data = try? Data(contentsOf: url) else { return nil }
  guard
    let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
      as? [String: Any]
  else {
    return nil
  }
  return obj
}

private func munkiVersion() -> String {
  guard let d = loadPlistDict(path: munkiVersionPlistPath) else { return "" }
  return (d["CFBundleShortVersionString"] as? String) ?? ""
}

private func installResults(from report: [String: Any]) -> [[String: Any]] {
  var out: [[String: Any]] = []

  if let items = report["InstallResults"] as? [[String: Any]] {
    for item in items {
      let status = (item["status"] as? Int) == 0 ? "installed" : "failed"
      var row: [String: Any] = [
        "item_name": item["name"] as? String ?? "",
        "item_version": item["version"] as? String ?? "",
        "status": status,
      ]
      if let t = jsonSafeTime(item["time"]) {
        row["install_date"] = t
      }
      out.append(row)
    }
  }

  if let items = report["RemovalResults"] as? [[String: Any]] {
    for item in items {
      let status = (item["status"] as? Int) == 0 ? "removed" : "removal_failed"
      out.append([
        "item_name": item["name"] as? String ?? "",
        "item_version": item["version"] as? String ?? "",
        "status": status,
      ])
    }
  }

  if let items = report["ProblemInstalls"] as? [[String: Any]] {
    for item in items {
      let name =
        (item["name"] as? String) ?? (item["display_name"] as? String) ?? ""
      out.append([
        "item_name": name,
        "item_version": item["version"] as? String ?? "",
        "status": "failed",
        "error_message": item["note"] as? String ?? "",
      ])
    }
  }

  return out
}

private func installedSoftwareFromInventory() -> [[String: Any]] {
  let url = URL(fileURLWithPath: applicationInventoryPath)
  guard let data = try? Data(contentsOf: url) else { return [] }
  guard
    let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
  else {
    return []
  }
  if let apps = obj as? [[String: Any]] {
    return apps.map { stringifyInventoryItem($0) }
  }
  if let dict = obj as? [String: Any], let apps = dict["applications"] as? [[String: Any]] {
    return apps.map { stringifyInventoryItem($0) }
  }
  return []
}

private func stringifyInventoryItem(_ app: [String: Any]) -> [String: Any] {
  let name =
    (app["CFBundleName"] as? String) ?? (app["name"] as? String) ?? ""
  return [
    "name": name,
    "version": (app["CFBundleShortVersionString"] as? String) ?? "",
    "bundle_id": (app["bundleid"] as? String) ?? "",
    "path": (app["path"] as? String) ?? "",
  ]
}

private func buildPayload() -> [String: Any]? {
  guard let report = loadPlistDict(path: managedInstallReportPath) else {
    logErr("automunki_postflight: no ManagedInstallReport.plist")
    return nil
  }

  let machineInfo = report["MachineInfo"] as? [String: Any] ?? [:]
  let serial =
    (machineInfo["serial_number"] as? String) ?? serialNumber()
  let hostname =
    (machineInfo["hostname"] as? String) ?? Host.current().localizedName ?? ""
  let osVersion =
    (machineInfo["os_vers"] as? String) ?? ProcessInfo.processInfo.operatingSystemVersionString
  let machineModel =
    (machineInfo["machine_model"] as? String) ?? sysctlString("hw.model") ?? ""
  let productNameStr = (machineInfo["product_name"] as? String) ?? ""
  let appleFamily = appleImageFamily(productName: productNameStr, machineModel: machineModel)

  let clientId = cfPrefString("ClientIdentifier" as CFString) ?? ""
  var manifestName = (report["ManifestName"] as? String) ?? ""
  if manifestName.isEmpty, !clientId.isEmpty {
    manifestName = clientId
  }

  let (diskTotal, diskFree) = diskStats()
  let ramMb = Int(ProcessInfo.processInfo.physicalMemory / 1024 / 1024)
  let buildVer = swVersBuildVersion()
  let arch = cpuArchString()
  let phyCpus: Int? = {
    guard let v = sysctlInt32("hw.physicalcpu"), v > 0 else { return nil }
    return Int(v)
  }()
  let logiCpus: Int? = {
    guard let v = sysctlInt32("hw.logicalcpu"), v > 0 else { return nil }
    return Int(v)
  }()

  // JSONSerialization rejects Swift Optionals embedded as Any; omit nil disk fields.
  var hardware: [String: Any] = [
    "hostname": hostname,
    "os_version": osVersion,
    "machine_model": machineModel,
    "cpu_type": cpuBrandString(),
    "cpu_arch": arch,
    "ram_mb": ramMb,
    "apple_image_family": appleFamily,
  ]
  if let pn = machineInfo["product_name"] as? String, !pn.isEmpty {
    hardware["product_name"] = pn
  }
  if !buildVer.isEmpty {
    hardware["os_build"] = buildVer
  }
  if let uuid = platformUUIDString() {
    hardware["platform_uuid"] = uuid
  }
  if let phyCpus {
    hardware["physical_cpus"] = phyCpus
  }
  if let logiCpus {
    hardware["logical_cpus"] = logiCpus
  }
  if let diskTotal {
    hardware["disk_size_gb"] = diskTotal
  }
  if let diskFree {
    hardware["disk_free_gb"] = diskFree
  }

  let installResultsPayload = installResults(from: report)
  let software = installedSoftwareFromInventory()

  var body: [String: Any] = [
    "serial_number": serial,
    "hostname": hostname,
    "os_version": osVersion,
    "machine_model": machineModel,
    "cpu_type": cpuBrandString(),
    "cpu_arch": arch,
    "ram_mb": ramMb,
    "munki_version": (machineInfo["munki_version"] as? String) ?? munkiVersion(),
    "manifest_name": manifestName,
    "client_identifier": clientId,
    "installed_software": software,
    "install_results": installResultsPayload,
    "hardware_info": hardware,
  ]
  if !buildVer.isEmpty {
    body["os_build"] = buildVer
  }
  if let phyCpus {
    body["physical_cpus"] = phyCpus
  }
  if let logiCpus {
    body["logical_cpus"] = logiCpus
  }
  if let diskTotal {
    body["disk_size_gb"] = diskTotal
  }
  if let diskFree {
    body["disk_free_gb"] = diskFree
  }
  return body
}

private func postCheckin(baseOrigin: String, payload: [String: Any]) {
  let trimmed = baseOrigin.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
  guard let url = URL(string: "\(trimmed)/api/v1/reports/checkin") else {
    logErr("automunki_postflight: invalid check-in URL (from SoftwareRepoURL origin)")
    return
  }

  guard JSONSerialization.isValidJSONObject(payload) else {
    logErr("automunki_postflight: payload is not JSON-serializable (check plist-derived values)")
    return
  }
  guard let body = try? JSONSerialization.data(withJSONObject: payload) else {
    logErr("automunki_postflight: could not serialize JSON")
    return
  }

  var request = URLRequest(url: url)
  request.httpMethod = "POST"
  request.setValue("application/json", forHTTPHeaderField: "Content-Type")
  request.httpBody = body

  let sem = DispatchSemaphore(value: 0)
  let task = URLSession.shared.dataTask(with: request) { data, response, error in
    defer { sem.signal() }
    if let error {
      logErr("automunki_postflight: \(error.localizedDescription)")
      return
    }
    guard let http = response as? HTTPURLResponse else { return }
    let text = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
    if (200...299).contains(http.statusCode) {
      fputs(
        "automunki_postflight: check-in OK \(http.statusCode) \(text)\n", stderr)
    } else {
      logErr("automunki_postflight: HTTP \(http.statusCode) \(text)")
    }
  }
  task.resume()
  sem.wait()
}

guard let repoURL = cfPrefString("SoftwareRepoURL" as CFString), !repoURL.isEmpty,
  let baseOrigin = apiBaseOrigin(fromSoftwareRepoURL: repoURL)
else {
  // No repo URL / unusable origin — do not fail Munki's run
  exit(0)
}

guard let payload = buildPayload() else {
  exit(0)
}

postCheckin(baseOrigin: baseOrigin, payload: payload)
exit(0)
