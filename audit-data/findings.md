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
