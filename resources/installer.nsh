;=================================================
; Predator — Custom NSIS Installer Theme
; Modern dark UI with red accents
;=================================================

; Use Modern UI 2
!include "MUI2.nsh"

;--------------------------------
; Installer Colors (dark theme)
;--------------------------------
!define MUI_CUSTOMFUNCTION_GUIINIT onGUIInit

; Override default colors
!define MUI_UI "${NSISDIR}\Contrib\UIs\modern.exe"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Header\modern_header.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "${NSISDIR}\Contrib\Graphics\Header\modern_header.bmp"

;--------------------------------
; Welcome/Finish Page Settings
;--------------------------------
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_TITLE_3LINES
!define MUI_WELCOMEPAGE_TITLE "Добро пожаловать в Predator"
!define MUI_WELCOMEPAGE_SUBTITLE "Программа проверки безопасности для GTA 5 RP"
!define MUI_FINISHPAGE_TITLE "Установка завершена!"
!define MUI_FINISHPAGE_SUBTITLE "Predator готов к работе."
!define MUI_FINISHPAGE_RUN "$INSTDIR\Predator.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Запустить Predator"
!define MUI_FINISHPAGE_NOREBOOT_SUPPORT

;--------------------------------
; Custom Macros for Styling
;--------------------------------

; Custom initialization
Function onGUIInit
  ; Set dark background color for dialogs
  SetCursors 1

  ; Apply custom colors to the installer window
  ; Note: For deeper customization, a custom UI file is needed
  ; The bitmap resources handle the visual theme
FunctionEnd

; Custom page display
Function .onVerifyInstDir
  ; Can add custom directory validation here
FunctionEnd

;--------------------------------
; Custom installer strings (Russian)
;--------------------------------
LangString MUI_TEXT_WELCOME_INFO_TITLE ${LANG_RUSSIAN} "Predator ${VERSION}"
LangString MUI_TEXT_WELCOME_INFO_TEXT ${LANG_RUSSIAN} "Этот мастер установит Predator — систему проверки безопасности для GTA 5 RP.$\r$\n$\r$\nПожалуйста, закройте все запущенные приложения перед установкой."

LangString MUI_TEXT_DIRECTORY_TITLE ${LANG_RUSSIAN} "Выберите папку установки"
LangString MUI_TEXT_DIRECTORY_SUBTITLE ${LANG_RUSSIAN} "Выберите папку, в которую будет установлен Predator."

LangString MUI_TEXT_INSTALLING_TITLE ${LANG_RUSSIAN} "Установка..."
LangString MUI_TEXT_INSTALLING_SUBTITLE ${LANG_RUSSIAN} "Пожалуйста, подождите, пока Predator устанавливается."

LangString MUI_TEXT_FINISH_TITLE ${LANG_RUSSIAN} "Установка завершена"
LangString MUI_TEXT_FINISH_SUBTITLE ${LANG_RUSSIAN} "Predator успешно установлен на ваш компьютер."

; English fallback
LangString MUI_TEXT_WELCOME_INFO_TITLE ${LANG_ENGLISH} "Welcome to Predator ${VERSION}"
LangString MUI_TEXT_WELCOME_INFO_TEXT ${LANG_ENGLISH} "This wizard will install Predator — security checker for GTA 5 RP.$\r$\n$\r$\nPlease close all running applications before installation."

LangString MUI_TEXT_DIRECTORY_TITLE ${LANG_ENGLISH} "Choose Install Location"
LangString MUI_TEXT_DIRECTORY_SUBTITLE ${LANG_ENGLISH} "Choose the folder where Predator will be installed."

LangString MUI_TEXT_INSTALLING_TITLE ${LANG_ENGLISH} "Installing..."
LangString MUI_TEXT_INSTALLING_SUBTITLE ${LANG_ENGLISH} "Please wait while Predator is being installed."

LangString MUI_TEXT_FINISH_TITLE ${LANG_ENGLISH} "Installation Complete"
LangString MUI_TEXT_FINISH_SUBTITLE ${LANG_ENGLISH} "Predator has been successfully installed."
