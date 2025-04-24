---
title: Protocol Audit Report
author: Naveen
date: April 20, 2024
titlepage: false
header-includes:
  - \usepackage{graphicx}
toc: true
---

\begin{titlepage}
\centering
\begin{figure}[h]
\centering
\includegraphics[width=0.5\textwidth]{logo.pdf}
\end{figure}
\vspace\*{2cm}
{\Huge\bfseries Protocol Audit Report\par}
\vspace{1cm}
{\Large Version 1.0\par}
\vspace{2cm}
{\Large\itshape Naveen\par}
\vfill
{\large \today\par}
\end{titlepage}

<!-- Your report starts here! -->

Prepared by: [Naveen](https://cyfrin.io)
Lead Auditors:

- Naveen

# Table of Contents

- [Table of Contents](#table-of-contents)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Roles](#roles)
- [Executive Summary](#executive-summary)
  - [Issues found](#issues-found)
- [Findings](#findings)
- [High](#high)
- [Medium](#medium)
- [Low](#low)
- [Informational](#informational)
- [Gas](#gas)

# Protocol Summary

PasswordStore is a protocol dedicated to storage and retrieval of a user's passwords. The protocol is designed to be used by a single user , and is not designed to be used by multiple users. Only the owner should be able to set and access this password.

# Disclaimer

The Naveen's team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details

## The findings described int this document correspond the following commit hash:\*\*

```
2e8f81e263b3a9d18fab4fb5c46805ffc10a9990
```

## Scope

```
./src/
└── PasswordStore.sol
```

## Roles

- Owner: The uer who can set the password and read the password
- Outsiders: No one else should be able to set or read the password

# Executive Summary

- The audit went smoothly. The codebase was generally well-structured and followed best practices, but a few critical and several low-to-medium severity issues were identified.
- We spent 2 hours with 1 auditor using 2 tools

## Issues found

    | Severity  |  Number of Issues found  |
    | --------- |  ----------------------- |
    | High      |             2            |
    | Medium    |             0            |
    | Low       |             0            |
    | Info      |             1            |
    | Total     |             3            |

# Findings

## High

### [H-1] Storing the Password On-Chain Makes It Visible to Anyone and No Longer Private

**Description:**  
All data stored on-chain is publicly accessible and can be read directly from the blockchain. The `PasswordStore::s_password` variable is intended to be a private variable and should only be accessed through the `PasswordStore::getPassword` function, which is intended to be called exclusively by the contract owner.

Below is a demonstration of how any data stored on-chain can be read off-chain.

**Impact:**  
Anyone can read the private password, severely compromising the security and functionality of the protocol.

**Proof of Concept:**

The following steps demonstrate how to read the password directly from the blockchain:

1. **Start a local blockchain:**

   ```bash
   make anvil
   ```

2. **Deploy the contract:**

   ```bash
   make deploy
   ```

3. **Read the storage slot:**

   Use slot `1` since that’s where `s_password` is stored.

   ```bash
   cast storage <ADDRESS_HERE> 1 --rpc-url http://127.0.0.1:8545
   ```

   You’ll get an output like:

   ```
   0x6d7950617373776f726400000000000000000000000000000000000000000014
   ```

4. **Decode the value:**

   ```bash
   cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
   ```

   Output:

   ```
   myPassword
   ```

**Recommended Mitigation:**  
This vulnerability calls for a redesign of the contract architecture. One solution is to encrypt the password off-chain and store only the encrypted version on-chain. However, this would require users to manage an off-chain decryption password. Additionally, consider removing the `view` function entirely to avoid exposing the password in transactions by mistake.

---

### [H-2] `PasswordStore::setPassword` Has No Access Controls, Allowing Anyone to Change the Password

**Description:**  
The `PasswordStore::setPassword` function is marked `external`. However, based on its NatSpec and the intended purpose of the contract, it is expected that **only the owner** should be allowed to set a new password.

```solidity
function setPassword(string memory newPassword) external {
    // @audit - There are no access controls
    s_password = newPassword;
    emit setNetPassword();
}
```

**Impact:**  
Anyone can set or change the contract password, completely undermining its intended behavior.

**Proof of Concept:**

<details>
<summary>Code</summary>

```solidity
function test_anyone_can_set_password(address randomAddress) public {
    vm.assume(randomAddress != owner);
    vm.prank(randomAddress);
    string memory expectedPassword = "myNewPassword";
    passwordStore.setPassword(expectedPassword);

    vm.prank(owner);
    string memory actualPassword = passwordStore.getPassword();
    assertEq(actualPassword, expectedPassword);
}
```

</details>

**Recommended Mitigation:**  
Add an access control check in `setPassword` to ensure only the contract owner can call it:

```solidity
if (msg.sender != s_owner) {
    revert PasswordStore__NotOwner();
}
```

---

## Informational

### [I-1] Incorrect NatSpec in `PasswordStore::getPassword`

**Description:**

```solidity
/*
 * @notice This allows only the owner to retrieve the password.
 * @param newPassword The new password to set.
 */
function getPassword() external view returns (string memory)
```

The NatSpec comment incorrectly references a parameter (`newPassword`) that does not exist in the function signature.

**Impact:**  
The NatSpec is misleading and incorrect, which may confuse developers and auditors.

**Recommended Mitigation:**  
Remove the invalid `@param` line from the comment block:

```diff
- * @param newPassword The new password to set.
```
