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
    ${If} $0 = 3
      MessageBox MB_YESNO|MB_ICONQUESTION "Защита Tunnel Guard сейчас включена. Её фильтры останутся в Windows и после удаления программы.$\r$\n$\r$\nДа — выключить защиту и удалить программу (прямой доступ в интернет вернётся).$\r$\nНет — удалить программу, оставив защиту (выбери при переустановке или обновлении; снять её потом можно, установив Tunnel Guard снова)." /SD IDNO IDNO tunnel_guard_keep_protection
      nsExec::ExecToStack '"$INSTDIR\guardctl.exe" protection disable --confirm'
      Pop $0
      Pop $1
      ${If} $0 <> 0
        MessageBox MB_OK|MB_ICONSTOP "Не удалось выключить защиту, поэтому удаление остановлено. Выключи её в Tunnel Guard и повтори." /SD IDOK
        Abort
      ${EndIf}
      tunnel_guard_keep_protection:
    ${EndIf}
  ${EndIf}
!macroend
