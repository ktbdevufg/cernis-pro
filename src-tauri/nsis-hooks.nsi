; CERNIS PRO NSIS Hooks
; Kill backend process before uninstall to avoid locked files

!macro NSIS_HOOK_PREUNINSTALL
  ; Kill cernis-backend.exe process tree before uninstalling
  nsExec::ExecToLog 'taskkill /F /IM cernis-backend.exe /T'
  nsExec::ExecToLog 'taskkill /F /IM cernis-pro.exe /T'
  Sleep 1000
!macroend

!macro NSIS_HOOK_PREINSTALL
  ; Kill running instance before installing (upgrade scenario)
  nsExec::ExecToLog 'taskkill /F /IM cernis-backend.exe /T'
  nsExec::ExecToLog 'taskkill /F /IM cernis-pro.exe /T'
  Sleep 1000
!macroend
