# 📝 Changelog - EnumRust

## [2.0.0] - 2025-10-11

### ✨ Dashboard v2.0 - Complete Redesign

#### 🎨 Visual Improvements
- **New Color Scheme**: Green (#10b981), Purple (#9333ea), Black (#000), White (#fff)
- **Modern UI**: Gradient effects, smooth animations, hover states
- **Responsive Design**: Works on all screen sizes
- **Cache-Busting**: Meta tags to prevent old version caching

#### 📁 File Explorer (NEW)
- **Two-Panel Layout**: File list (left) + content viewer (right)
- **Terminal-Style Viewer**: Green text on black background
- **File Size Display**: Shows size in KB for each file
- **Domain-Specific Navigation**: Browse files by selected domain
- **Syntax Highlighting**: Colored output for better readability

#### 🔍 Enhanced Filtering
- **Domain Selector**: Dropdown to filter data by specific domain
- **Vulnerability Filters**: All/Critical/High/Medium/Low with counters
- **Real-time Updates**: Auto-refresh every 5 seconds
- **Smart Data Separation**: Each domain's data completely isolated

#### 🚀 New Features
- **Progress Monitoring**: Animated progress bar with percentage
- **Event Stream**: Live feed of tool execution
- **Statistics Cards**: Real-time vulnerability and port counts
- **JWT Authentication**: Secure dashboard access

### 🔧 Bug Fixes
- **Masscan Error**: Fixed "target IP address list empty" error
  - Now checks if ips.txt has content before running masscan
  - Gracefully skips masscan if no IPs found
  - Displays informative message instead of error

### 🧹 Code Cleanup
- **Directory Structure**: Removed old scan result directories
- **Reduced Size**: From 5.8GB to 1.7GB (~70% reduction)
- **Removed Files**:
  - Old domain scan directories (emprel.gov.br, example.com, etc.)
  - HBCD_PE_x64.iso (~600MB)
  - Duplicate documentation files
  - Test scripts and temporary files
  - Debug build artifacts
- **Organized Documentation**: Consolidated into main README.md

### 📚 Documentation
- **Updated README.md**: Modern, comprehensive guide
- **New run-dashboard.sh**: Easy dashboard launcher script
- **Preserved Key Docs**:
  - QUICK_START.md
  - METASPLOIT_INTEGRATION.md
  - INFRASTRUCTURE_MODE.md
  - IP_FORMATS.md
  - DASHBOARD_IMPROVEMENTS.md
  - DASHBOARD_DOMAIN_FILTER.md

### 🛠️ Technical Improvements

#### Backend (src/dashboard.rs)
```rust
// New API endpoints
GET /api/domain/:domain/files      // List files in domain directory
GET /api/file/*file_path           // Read file content (with security checks)
GET /api/domain/:domain/data       // Get domain-specific data
```

#### Frontend (dashboard-ui/index.html)
- **React Components**: FileExplorer, VulnerabilitiesTab, PortsTab, ProgressMonitor
- **CSS Variables**: Centralized theming system
- **Animations**: slideIn, pulse, glow effects
- **Auto-refresh Logic**: Intelligent update intervals

### 🔐 Security
- **Path Validation**: Prevents directory traversal attacks
- **File Size Limits**: 100KB max for viewer to prevent browser slowdown
- **Input Sanitization**: Safe file path handling
- **JWT Token Verification**: All API endpoints protected

---

## [1.0.0] - Previous Version

### Features
- Basic subdomain enumeration
- Port scanning with masscan
- Vulnerability scanning with Nuclei
- Simple dashboard interface
- Infrastructure scanning mode

---

## 📊 Statistics

### Before Cleanup
- **Size**: 5.8GB
- **Files**: 50+ files and directories
- **Scan Results**: Mixed together, hard to navigate

### After Cleanup
- **Size**: 1.7GB (70% reduction)
- **Files**: 26 organized files
- **Scan Results**: Separated by domain, easy to explore

---

## 🚀 Upgrade Instructions

### From v1.x to v2.0

1. **Pull latest changes**:
   ```bash
   cd /root/PENTEST/enumrust/enumrust
   git pull
   ```

2. **Rebuild**:
   ```bash
   cargo build --release
   ```

3. **Clear browser cache** when accessing dashboard:
   - **Chrome/Firefox**: `Ctrl+Shift+R` (Linux/Windows) or `Cmd+Shift+R` (Mac)
   - Or close browser completely and reopen

4. **Launch new dashboard**:
   ```bash
   ./run-dashboard.sh
   ```

---

## 📝 Notes

- **Breaking Changes**: None - backward compatible with v1.x scan results
- **Security**: Credentials are now generated randomly at runtime

---

## 🎯 Coming Soon

- [ ] Export reports to PDF/HTML
- [ ] Integration with CI/CD pipelines
- [ ] Multi-user support with role-based access
- [ ] Scheduled scans
- [ ] Email notifications for critical findings
- [ ] API documentation with Swagger
- [ ] Docker containerization

---

## 👤 Maintainer

**OFJAAAH**

For issues or feature requests, please open a GitHub issue.

---

**Last Updated**: October 11, 2025
