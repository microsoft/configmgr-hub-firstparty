$CMUpdatesStore = New-Object -ComObject Microsoft.CCM.UpdatesStore
$CMUpdatesStore.RefreshServerComplianceState()