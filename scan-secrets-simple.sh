#!/bin/bash

# QubeNode Security Scanner - Simple Version (No Git Required)
# Scans for secrets, API keys, passwords, and sensitive data
# Created: 2025-12-13

echo "🔍 QubeNode Security Scanner (Simple Mode)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_ISSUES=0
CRITICAL_ISSUES=0
WARNING_ISSUES=0

# Function to print findings
print_finding() {
    local severity=$1
    local file=$2
    local line=$3
    local pattern=$4
    local match=$5
    
    if [ "$severity" = "CRITICAL" ]; then
        echo -e "${RED}[CRITICAL]${NC} $file:$line"
        echo -e "  Pattern: $pattern"
        echo -e "  Match: ${RED}$match${NC}"
        echo ""
        ((CRITICAL_ISSUES++))
    elif [ "$severity" = "WARNING" ]; then
        echo -e "${YELLOW}[WARNING]${NC} $file:$line"
        echo -e "  Pattern: $pattern"
        echo -e "  Match: $match"
        echo ""
        ((WARNING_ISSUES++))
    fi
    
    ((TOTAL_ISSUES++))
}

echo "📂 Scanning current directory: $(pwd)"
echo ""

# Create temporary file list
TEMP_FILE_LIST=$(mktemp)
find . -type f \( -name "*.html" -o -name "*.js" -o -name "*.json" -o -name "*.md" -o -name "*.txt" -o -name "*.css" \) ! -path "*/node_modules/*" ! -path "*/.git/*" ! -path "*/dist/*" ! -path "*/build/*" > "$TEMP_FILE_LIST"

FILE_COUNT=$(wc -l < "$TEMP_FILE_LIST")
echo "✅ Found $FILE_COUNT files to scan"
echo ""

# 1. CRITICAL: API Keys
echo "🔑 [1/10] Scanning for API keys..."
while IFS= read -r file; do
    if [ -f "$file" ]; then
        grep -nHi -E "api[_-]?key|apikey|api[_-]?secret|client[_-]?secret" "$file" 2>/dev/null | while IFS=: read -r fname line content; do
            # Skip comments
            if ! echo "$content" | grep -qE "^\s*(//|#|\*|/\*)"; then
                # Skip if it's just a variable name
                if ! echo "$content" | grep -qiE "(apikey|api_key|apisecret)\s*[:=]\s*['\"]?\s*['\"]?\s*[,;]?\s*$"; then
                    print_finding "CRITICAL" "$fname" "$line" "API Key" "$content"
                fi
            fi
        done
    fi
done < "$TEMP_FILE_LIST"

# 2. CRITICAL: Private Keys
echo "🔐 [2/10] Scanning for private keys..."
while IFS= read -r file; do
    if [ -f "$file" ]; then
        grep -nHi -E "private[_-]?key|privatekey|-----BEGIN.*PRIVATE KEY-----" "$file" 2>/dev/null | while IFS=: read -r fname line content; do
            if ! echo "$content" | grep -qE "^\s*(//|#|\*|/\*)"; then
                print_finding "CRITICAL" "$fname" "$line" "Private Key" "$content"
            fi
        done
    fi
done < "$TEMP_FILE_LIST"

# 3. CRITICAL: Wallet Seeds/Mnemonics
echo "🌱 [3/10] Scanning for wallet seeds..."
while IFS= read -r file; do
    if [ -f "$file" ]; then
        grep -nHi -E "mnemonic|seed[_-]?phrase|recovery[_-]?phrase" "$file" 2>/dev/null | while IFS=: read -r fname line content; do
            # Skip variable declarations and comments
            if ! echo "$content" | grep -qE "^\s*(//|#|\*|/\*|const|let|var|function)"; then
                # Skip if it's just asking for mnemonic (not storing it)
                if ! echo "$content" | grep -qiE "(enter|input|type|provide|paste).*mnemonic"; then
                    print_finding "CRITICAL" "$fname" "$line" "Wallet Seed/Mnemonic" "$content"
                fi
            fi
        done
    fi
done < "$TEMP_FILE_LIST"

# 4. CRITICAL: Passwords
echo "🔒 [4/10] Scanning for passwords..."
while IFS= read -r file; do
    if [ -f "$file" ]; then
        grep -nHi -E "password\s*[:=]|passwd\s*[:=]|pwd\s*[:=]" "$file" 2>/dev/null | while IFS=: read -r fname line content; do
            if ! echo "$content" | grep -qE "^\s*(//|#|\*|/\*)"; then
                # Skip if it's just a variable name or placeholder
                if ! echo "$content" | grep -qiE "(password|passwd|pwd)\s*[:=]\s*['\"]?\s*['\"]?\s*[,;]?\s*$"; then
                    # Skip common false positives
                    if ! echo "$content" | grep -qiE "type.*password|input.*password|placeholder.*password"; then
                        print_finding "CRITICAL" "$fname" "$line" "Password" "$content"
                    fi
                fi
            fi
        done
    fi
done < "$TEMP_FILE_LIST"

# 5. WARNING: Tokens
echo "🎫 [5/10] Scanning for tokens..."
while IFS= read -r file; do
    if [ -f "$file" ]; then
        grep -nHi -E "token\s*[:=]|auth[_-]?token|access[_-]?token|bearer" "$file" 2>/dev/null | while IFS=: read -r fname line content; do
            if ! echo "$content" | grep -qE "^\s*(//|#|\*|/\*)"; then
                # Skip if it's localStorage or just a variable
                if ! echo "$content" | grep -qiE "localStorage|getItem|setItem|token\s*[:=]\s*['\"]?\s*['\"]?\s*[,;]?\s*$"; then
                    print_finding "WARNING" "$fname" "$line" "Token" "$content"
                fi
            fi
        done
    fi
done < "$TEMP_FILE_LIST"

# 6. WARNING: Email addresses with passwords nearby
echo "📧 [6/10] Scanning for credentials..."
while IFS= read -r file; do
    if [ -f "$file" ]; then
        grep -nHi -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$file" 2>/dev/null | while IFS=: read -r fname line content; do
            # Check if password appears in same file within 5 lines
            start_line=$((line - 5))
            end_line=$((line + 5))
            if [ $start_line -lt 1 ]; then start_line=1; fi
            
            if sed -n "${start_line},${end_line}p" "$fname" 2>/dev/null | grep -qi "password\|passwd\|pwd"; then
                print_finding "WARNING" "$fname" "$line" "Email with password nearby" "$content"
            fi
        done
    fi
done < "$TEMP_FILE_LIST"

# 7. CRITICAL: Hardcoded URLs with credentials
echo "🌐 [7/10] Scanning for URLs with credentials..."
while IFS= read -r file; do
    if [ -f "$file" ]; then
        grep -nHi -E "https?://[^:]+:[^@]+@" "$file" 2>/dev/null | while IFS=: read -r fname line content; do
            if ! echo "$content" | grep -qE "^\s*(//|#|\*|/\*)"; then
                print_finding "CRITICAL" "$fname" "$line" "URL with credentials" "$content"
            fi
        done
    fi
done < "$TEMP_FILE_LIST"

# 8. WARNING: Hardcoded validator operator addresses (potential info disclosure)
echo "🔑 [8/10] Scanning for validator operator addresses..."
while IFS= read -r file; do
    if [ -f "$file" ]; then
        grep -nHo -E "qubeticsvaloper[a-z0-9]{39}" "$file" 2>/dev/null | while IFS=: read -r fname line valoper; do
            # This is actually OK - it's public info, but let's log it
            # Skip this check - validator address is public
            :
        done
    fi
done < "$TEMP_FILE_LIST"

# 9. INFO: Large base64 strings (might be keys)
echo "📦 [9/10] Scanning for large base64 strings..."
while IFS= read -r file; do
    if [ -f "$file" ]; then
        grep -nHo -E "[A-Za-z0-9+/]{100,}={0,2}" "$file" 2>/dev/null | while IFS=: read -r fname line b64; do
            # Only report if it's really long (likely a key)
            if [ ${#b64} -gt 200 ]; then
                print_finding "WARNING" "$fname" "$line" "Large base64 string (potential key)" "${b64:0:50}..."
            fi
        done
    fi
done < "$TEMP_FILE_LIST"

# 10. Check for .env files
echo "📄 [10/10] Checking for .env files..."
find . -type f -name ".env*" ! -path "*/node_modules/*" ! -path "*/.git/*" 2>/dev/null | while read -r envfile; do
    print_finding "CRITICAL" "$envfile" "0" ".env file found" "Environment files should not be in public directories"
done

# Cleanup
rm -f "$TEMP_FILE_LIST"

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 SCAN SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ $CRITICAL_ISSUES -eq 0 ] && [ $WARNING_ISSUES -eq 0 ]; then
    echo -e "${GREEN}✅ NO ISSUES FOUND!${NC}"
    echo ""
    echo "Your files appear to be clean of common secrets."
    echo ""
    echo "📁 Scanned directory: $(pwd)"
    echo "📄 Files checked: $FILE_COUNT"
    exit 0
else
    echo -e "${RED}Critical Issues: $CRITICAL_ISSUES${NC}"
    echo -e "${YELLOW}Warnings: $WARNING_ISSUES${NC}"
    echo -e "Total Findings: $TOTAL_ISSUES"
    echo ""
    
    if [ $CRITICAL_ISSUES -gt 0 ]; then
        echo -e "${RED}⚠️  CRITICAL: Immediate action required!${NC}"
        echo ""
        echo "Recommended actions:"
        echo "1. Remove sensitive data from files"
        echo "2. Rotate all exposed credentials"
        echo "3. Use environment variables for secrets"
        echo "4. Never commit sensitive data to repositories"
        exit 1
    else
        echo -e "${YELLOW}⚠️  Review warnings and address if needed${NC}"
        echo ""
        echo "Most warnings are informational - review each one carefully."
        exit 0
    fi
fi
