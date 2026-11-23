; Tunnel Guard's WFP filters are persistent on purpose: they keep blocking
; traffic outside the tunnel across reboots and outlive the program. Removing
; the program must neither leave the PC silently offline nor silently drop the
; protection, so the uninstaller asks. Updates (/UPDATE) keep the filters.
!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode <> 1
  ${AndIf} ${FileExists} "$INSTDIR\guardctl.exe"
    nsExec::ExecToStack '"$INSTDIR\guardctl.exe" protection active'
    Pop $0
    Pop $1
    ; 3: the guard is in force. Anything else but 0 (guardctl failed, damaged
    ; settings, "error" from nsExec) means the state is unknown: ask as well.
    ${If} $0 == 3
      MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "Защита Tunnel Guard сейчас включена. Её фильтры останутся в Windows и после удаления программы.$\r$\n$\r$\nДа — выключить защиту и удалить программу (прямой доступ в интернет вернётся).$\r$\nНет — удалить программу, оставив защиту (выбери при переустановке или обновлении; снять её потом можно, установив Tunnel Guard снова)." /SD IDNO IDNO tunnel_guard_keep_protection
    ${ElseIf} $0 != 0
      MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 "Не удалось проверить, включена ли защита Tunnel Guard. Если включена, её фильтры останутся в Windows и после удаления программы.$\r$\n$\r$\nДа — попытаться выключить защиту и удалить программу.$\r$\nНет — удалить программу, ничего не меняя в защите." /SD IDNO IDNO tunnel_guard_keep_protection
    ${Else}
      Goto tunnel_guard_keep_protection
    ${EndIf}
    nsExec::ExecToStack '"$INSTDIR\guardctl.exe" protection disable --confirm'
    Pop $0
    Pop $1
    ${If} $0 != 0
      MessageBox MB_OK|MB_ICONSTOP "Не удалось выключить защиту, поэтому удаление остановлено. Выключи её в Tunnel Guard и повтори." /SD IDOK
      Abort
    ${EndIf}
    tunnel_guard_keep_protection:
  ${EndIf}
!macroend

; Versions up to 0.6.0-preview.4 were installed for the current user only, in
; a folder any of the user's programs can write to, and that copy still asks
; for administrator rights. Offer to remove it. Its uninstaller runs with the
; user's rights (never elevated: the file may have been replaced) and has no
; hook, so it leaves the protection as it is.
!macro NSIS_HOOK_PREINSTALL
  Push $R0
  Push $R1
  ReadRegStr $R0 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCTNAME}" "UninstallString"
  StrCpy $R1 $R0 1
  ${If} $R1 == '"'
    StrCpy $R0 $R0 -1 1
  ${EndIf}
  ${If} $R0 != ""
  ${AndIf} ${FileExists} "$R0"
  ${AndIf} $R0 != "$INSTDIR\uninstall.exe"
    MessageBox MB_YESNO|MB_ICONEXCLAMATION "Найдена старая копия Tunnel Guard, установленная только для текущего пользователя:$\r$\n$R0$\r$\n$\r$\nЕё файлы может подменить любая программа без прав администратора, а сама копия запрашивает права администратора. Удалить её? Защита при этом не меняется." /SD IDYES IDNO tunnel_guard_keep_old_copy
    nsis_tauri_utils::RunAsUser "$R0" "/S"
    tunnel_guard_keep_old_copy:
  ${EndIf}
  Pop $R1
  Pop $R0
!macroend
