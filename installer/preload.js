const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('installerAPI', {
  // Window controls
  minimize: () => ipcRenderer.invoke('window-minimize'),
  close: () => ipcRenderer.invoke('window-close'),

  // Install directory
  getDefaultPath: () => ipcRenderer.invoke('get-default-path'),
  selectDirectory: () => ipcRenderer.invoke('select-directory'),

  // Download & install
  downloadPredator: (options) => ipcRenderer.invoke('download-predator', options),
  createShortcuts: (options) => ipcRenderer.invoke('create-shortcuts', options),
  launchPredator: (exePath) => ipcRenderer.invoke('launch-predator', exePath),

  // Download progress
  onDownloadProgress: (callback) => {
    ipcRenderer.on('download-progress', (_event, data) => callback(data))
  },
})
