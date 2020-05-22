$PowerPlan=Get-WmiObject -Namespace "Root\Cimv2\Power" -Class Win32_PowerPlan | Where {$_.IsActive}
# Can be Balanced, High performance or Power saver
$PowerPlan.Elementname