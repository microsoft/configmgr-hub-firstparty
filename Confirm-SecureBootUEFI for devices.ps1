$Status = Confirm-SecurebootUEFI
if ($status) {
   write-host "SecureBoot=True"
} Else {
   write-host "SecureBoot=False"
}