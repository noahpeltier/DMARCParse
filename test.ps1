$Password = "FartMan23!"
$PossibleCharacters = Get-StringScore $Password
$l = $Password.Length
$s = $PossibleCharacters #95

$PossibleCombinations = [bigint]::Pow($s, $l)

$Entropy = [math]::floor([math]::Log2($PossibleCombinations))
$NumberOfGuesses = [bigint]::Pow(2, ($Entropy))


##################################
cls
"Bits of entropy: $Entropy"


# Function to convert numbers to words
function Convert-NumberToWords {
    param ([bigint]$number)

    $units = @("zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine")
    $tens = @("ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen")
    $twenties = @("twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety")
    $thousands = @("thousand", "million", "billion", "trillion", "quadrillion", "quintillion", "sextillion", "septillion", "octillion", "nonillion")

    if ($number -lt 10) {
        return $units[$number]
    }
    elseif ($number -lt 20) {
        return $tens[$number - 10]
    }
    elseif ($number -lt 100) {
        $tensPart = $twenties[([math]::floor($number / 10)) - 2]
        $unitsPart = $number % 10
        if ($unitsPart -eq 0) {
            return $tensPart
        }
        else {
            return "$tensPart-$($units[$unitsPart])"
        }
    }
    else {
        $numberStr = $number.ToString()
        $numberLength = $numberStr.Length
        $chunks = [math]::Ceiling($numberLength / 3)

        $words = ""
        for ($i = 0; $i -lt $chunks; $i++) {
            $chunkValue = [bigint]$numberStr.Substring(0, $numberLength - 3 * $i)
            $chunkValue = [bigint]$chunkValue.ToString().Substring(0, $chunkValue.ToString().Length - ($chunks - 1 - $i) * 3)
            if ($chunkValue -gt 0) {
                if ($i -gt 0) {
                    $words = "$chunkValue $($thousands[$chunks - 2 - $i]) " + $words
                }
                else {
                    $words = "$chunkValue " + $words
                }
            }
        }
        return $words.Trim()
    }
}
function Get-StringScore {
    param (
        [string]$inputString
    )

    # Define the score values
    $scoreMap = @{
        "numbers"      = 10
        "lowercase"    = 26
        "uppercase"    = 26
        "specialChars" = 32
    }

    # Initialize flags for each category
    $hasNumbers = $false
    $hasLowercase = $false
    $hasUppercase = $false
    $hasSpecialChars = $false

    # Check each character in the string to see which categories it belongs to
    foreach ($char in $inputString.ToCharArray()) {
        if ($char -match '[0-9]') {
            $hasNumbers = $true
        }
        elseif ($char -match '[a-z]') {
            $hasLowercase = $true
        }
        elseif ($char -cmatch '[A-Z]') {
            $hasUppercase = $true
        }
        elseif ($char -match '[^a-zA-Z0-9]') {
            $hasSpecialChars = $true
        }
    }

    # Calculate the total score based on which categories are present
    $totalScore = 0
    if ($hasNumbers) {
        $totalScore += $scoreMap["numbers"]
    }
    if ($hasLowercase) {
        $totalScore += $scoreMap["lowercase"]
    }
    if ($hasUppercase) {
        $totalScore += $scoreMap["uppercase"]
    }
    if ($hasSpecialChars) {
        $totalScore += $scoreMap["specialChars"]
    }

    return $totalScore
}

function Get-StringScore {
    param(
        $string
    )
    $Score = 0
    switch ($string) {

        { $string -cmatch '[A-Z]' } { $score += 26 }
        { $string -match '[A-Z]' } { $score += 26 }
        { $string -match '[0-9]' } { $score += 10 }
        { $string -match '[^a-zA-Z0-9 ]' } { $score += 32 }
    }

    return $score
}

$singleguess = .010
$numattackers = 100
$secondsperguess = $singleguess / $numattackers
[bigint](.5 * [math]::pow(2, $Entropy) * $secondsperguess)

function log2 {
    [math]::Log2($args[0])
}