# Variable Validation Outside of Parameters
## ValidateRange
[ValidateRange(1,10)][int]$ValidateRange = 1
$ValidateRange = 3
$ValidateRange = 11

## ValidateSet
[ValidateSet('Test1','Test2','Test3')][string]$ValidateSet = 'Test1'
$ValidateSet = 'Test2'
$ValidateSet = 'Test4'

## ValidateNotNullOrEmpty
[ValidateNotNullOrEmpty()][string]$ValidateNotNullOrEmpty = 'Test1'
$ValidateNotNullOrEmpty = 'Test'
$ValidateNotNullOrEmpty = ''

## ValidateCount
[ValidateCount(1,10)][array]$ValidateCount = @(1..9)
$ValidateCount += 'test'
$ValidateCount += 'test2'

## ValidateLength
[ValidateCount(1,10)][string]$ValidateLength = 'Test1'
$ValidateLength = 'Testing2'
$ValidateLength = 'TestOverTen'

## ValidatePattern
[ValidatePattern('^\d{3}[-.]?\d{3}[-.]?\d{4}$')][string]$ValidatePattern = '800-123-4567'
$ValidatePattern = '000-000-0000'
$ValidatePattern = '000-000-00000'

## ValidateScript
[ValidateScript({Test-Path $_})][string]$ValidateScript = 'C:\Windows\System32\cmd.exe'
$ValidateScript = 'C:\Windows\System32\powercfg.exe'
$ValidateScript = 'C:\Windows\System32\DoesNotExist.exe'
