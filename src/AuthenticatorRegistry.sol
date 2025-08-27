// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {LeanIMT, LeanIMTData} from "./tree/LeanIMT.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract AuthenticatorRegistry is EIP712 {
    using LeanIMT for LeanIMTData;
    using EnumerableSet for EnumerableSet.AddressSet;

    ////////////////////////////////////////////////////////////
    //                        Members                         //
    ////////////////////////////////////////////////////////////

    mapping(uint256 => address) public accountIndexToRecoveryAddress;
    mapping(address => uint256) public authenticatorAddressToAccountIndex;
    mapping(uint256 => uint256) public signatureNonces;
    mapping(uint256 => EnumerableSet.AddressSet) internal accountAuthenticators;

    LeanIMTData public tree;
    uint256 public nextAccountIndex = 1;

    ////////////////////////////////////////////////////////////
    //                        Events                          //
    ////////////////////////////////////////////////////////////

    event AccountCreated(
        uint256 indexed accountIndex,
        address indexed recoveryAddress,
        address[] authenticatorAddresses,
        uint256 offchainSignerCommitment
    );
    event AccountUpdated(
        uint256 indexed accountIndex,
        address indexed oldAuthenticatorAddress,
        address indexed newAuthenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event AccountRecovered(
        uint256 indexed accountIndex,
        address indexed newAuthenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event AuthenticatorInserted(
        uint256 indexed accountIndex,
        address indexed authenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );
    event AuthenticatorRemoved(
        uint256 indexed accountIndex,
        address indexed authenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment
    );

    ////////////////////////////////////////////////////////////
    //                        Constants                       //
    ////////////////////////////////////////////////////////////

    string public constant UPDATE_AUTHENTICATOR_TYPEDEF =
        "UpdateAuthenticator(uint256 accountIndex, address oldAuthenticatorAddress, address newAuthenticatorAddress, uint256 newOffchainSignerCommitment, uint256 nonce)";
    string public constant INSERT_AUTHENTICATOR_TYPEDEF =
        "InsertAuthenticator(uint256 accountIndex, address newAuthenticatorAddress, uint256 newOffchainSignerCommitment, uint256 nonce)";
    string public constant REMOVE_AUTHENTICATOR_TYPEDEF =
        "RemoveAuthenticator(uint256 accountIndex, address authenticatorAddress, uint256 newOffchainSignerCommitment, uint256 nonce)";
    string public constant RECOVER_ACCOUNT_TYPEDEF =
        "RecoverAccount(uint256 accountIndex, address newAuthenticatorAddress, uint256 newOffchainSignerCommitment, uint256 nonce)";

    bytes32 public constant UPDATE_AUTHENTICATOR_TYPEHASH = keccak256(abi.encodePacked(UPDATE_AUTHENTICATOR_TYPEDEF));
    bytes32 public constant INSERT_AUTHENTICATOR_TYPEHASH = keccak256(abi.encodePacked(INSERT_AUTHENTICATOR_TYPEDEF));
    bytes32 public constant REMOVE_AUTHENTICATOR_TYPEHASH = keccak256(abi.encodePacked(REMOVE_AUTHENTICATOR_TYPEDEF));
    bytes32 public constant RECOVER_ACCOUNT_TYPEHASH = keccak256(abi.encodePacked(RECOVER_ACCOUNT_TYPEDEF));

    string public constant EIP712_NAME = "AuthenticatorRegistry";
    string public constant EIP712_VERSION = "1.0";

    ////////////////////////////////////////////////////////////
    //                        Constructor                     //
    ////////////////////////////////////////////////////////////

    constructor() EIP712(EIP712_NAME, EIP712_VERSION) {}

    ////////////////////////////////////////////////////////////
    //                        Functions                       //
    ////////////////////////////////////////////////////////////

    function domainSeparatorV4() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev Recovers the account index from a message hash and a signature.
     * @param messageHash The message hash.
     * @param signature The signature.
     * @return The account index.
     */
    function recoverAccountIndex(bytes32 messageHash, bytes memory signature) internal view returns (uint256) {
        address signatureRecoveredAddress = ECDSA.recover(messageHash, signature);
        require(signatureRecoveredAddress != address(0), "Invalid signature");
        uint256 accountIndex = authenticatorAddressToAccountIndex[signatureRecoveredAddress];
        require(accountIndex != 0, "Account does not exist");
        return accountIndex;
    }

    /**
     * @dev Creates a new account.
     * @param recoveryAddress The address of the recovery signer.
     * @param authenticatorAddresses The addresses of the authenticators.
     * @param offchainSignerCommitment The offchain signer commitment.
     */
    function createAccount(
        address recoveryAddress,
        address[] calldata authenticatorAddresses,
        uint256 offchainSignerCommitment
    ) public {
        require(authenticatorAddresses.length > 0, "authenticatorAddresses length must be greater than 0");
        accountIndexToRecoveryAddress[nextAccountIndex] = recoveryAddress;

        for (uint256 i = 0; i < authenticatorAddresses.length; i++) {
            require(authenticatorAddressToAccountIndex[authenticatorAddresses[i]] == 0, "Authenticator already exists");
            require(authenticatorAddresses[i] != address(0), "Authenticator cannot be the zero address");
            require(
                accountAuthenticators[nextAccountIndex].add(authenticatorAddresses[i]), "Adding authenticator failed"
            );
            authenticatorAddressToAccountIndex[authenticatorAddresses[i]] = nextAccountIndex;
        }

        // Update tree
        tree.insert(offchainSignerCommitment);

        emit AccountCreated(nextAccountIndex, recoveryAddress, authenticatorAddresses, offchainSignerCommitment);

        nextAccountIndex++;
    }

    /**
     * @dev Creates multiple accounts.
     * @param recoveryAddresses The addresses of the recovery signers.
     * @param authenticatorAddresses The addresses of the authenticators.
     * @param offchainSignerCommitments The offchain signer commitments.
     */
    function createManyAccounts(
        address[] calldata recoveryAddresses,
        address[][] calldata authenticatorAddresses,
        uint256[] calldata offchainSignerCommitments
    ) public {
        require(recoveryAddresses.length > 0, "Length must be greater than 0");
        require(
            recoveryAddresses.length == authenticatorAddresses.length,
            "Recovery addresses and authenticator addresses length mismatch"
        );
        require(
            recoveryAddresses.length == offchainSignerCommitments.length,
            "Recovery addresses and offchain signer commitments length mismatch"
        );

        for (uint256 i = 0; i < recoveryAddresses.length; i++) {
            require(authenticatorAddresses[i].length > 0, "Authenticator addresses length must be greater than 0");
            accountIndexToRecoveryAddress[nextAccountIndex] = recoveryAddresses[i];
            for (uint256 j = 0; j < authenticatorAddresses[i].length; j++) {
                require(
                    authenticatorAddressToAccountIndex[authenticatorAddresses[i][j]] == 0,
                    "Authenticator already exists"
                );
                require(authenticatorAddresses[i][j] != address(0), "Authenticator cannot be the zero address");
                require(
                    accountAuthenticators[nextAccountIndex].add(authenticatorAddresses[i][j]),
                    "Adding authenticator failed"
                );
                authenticatorAddressToAccountIndex[authenticatorAddresses[i][j]] = nextAccountIndex;
            }

            nextAccountIndex++;
            emit AccountCreated(
                nextAccountIndex, recoveryAddresses[i], authenticatorAddresses[i], offchainSignerCommitments[i]
            );
        }

        // Update tree
        tree.insertMany(offchainSignerCommitments);
    }

    /**
     * @dev Updates an existing authenticator.
     * @param oldAuthenticatorAddress The authenticator address to update.
     * @param newAuthenticatorAddress The new authenticator address.
     * @param oldOffchainSignerCommitment The old offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     */
    function updateAuthenticator(
        uint256 accountIndex,
        address oldAuthenticatorAddress,
        address newAuthenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) public {
        require(authenticatorAddressToAccountIndex[oldAuthenticatorAddress] != 0, "Authenticator does not exist");
        require(authenticatorAddressToAccountIndex[newAuthenticatorAddress] == 0, "Authenticator already exists");
        require(
            oldAuthenticatorAddress != newAuthenticatorAddress, "Old and new authenticator addresses cannot be the same"
        );
        require(newAuthenticatorAddress != address(0), "New authenticator address cannot be the zero address");

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    UPDATE_AUTHENTICATOR_TYPEHASH,
                    accountIndex,
                    oldAuthenticatorAddress,
                    newAuthenticatorAddress,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        require(accountIndex == recoverAccountIndex(messageHash, signature), "Invalid account index");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");
        require(
            authenticatorAddressToAccountIndex[oldAuthenticatorAddress] == accountIndex,
            "Authenticator does not belong to account"
        );

        // Delete old authenticator
        require(accountAuthenticators[accountIndex].remove(oldAuthenticatorAddress), "Removing authenticator failed");
        delete authenticatorAddressToAccountIndex[oldAuthenticatorAddress];

        // Add new authenticator
        require(accountAuthenticators[accountIndex].add(newAuthenticatorAddress), "Adding authenticator failed");
        authenticatorAddressToAccountIndex[newAuthenticatorAddress] = accountIndex;

        // Update tree
        tree.update(accountIndex - 1, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        emit AccountUpdated(
            accountIndex,
            oldAuthenticatorAddress,
            newAuthenticatorAddress,
            oldOffchainSignerCommitment,
            newOffchainSignerCommitment
        );
    }

    /**
     * @dev Inserts a new authenticator.
     * @param newAuthenticatorAddress The authenticator address to insert.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     */
    function insertAuthenticator(
        uint256 accountIndex,
        address newAuthenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) public {
        require(newAuthenticatorAddress != address(0), "New authenticator address cannot be the zero address");
        require(authenticatorAddressToAccountIndex[newAuthenticatorAddress] == 0, "Authenticator already exists");

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    INSERT_AUTHENTICATOR_TYPEHASH,
                    accountIndex,
                    newAuthenticatorAddress,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        require(accountIndex == recoverAccountIndex(messageHash, signature), "Invalid account index");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");

        // Add new authenticator
        require(accountAuthenticators[accountIndex].add(newAuthenticatorAddress), "Adding authenticator failed");
        authenticatorAddressToAccountIndex[newAuthenticatorAddress] = accountIndex;

        // Update tree
        tree.update(accountIndex - 1, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        emit AuthenticatorInserted(
            accountIndex, newAuthenticatorAddress, oldOffchainSignerCommitment, newOffchainSignerCommitment
        );
    }

    /**
     * @dev Removes an authenticator.
     * @param authenticatorAddress The authenticator address to remove.
     * @param oldOffchainSignerCommitment The old offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     */
    function removeAuthenticator(
        uint256 accountIndex,
        address authenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) public {
        require(authenticatorAddressToAccountIndex[authenticatorAddress] != 0, "Authenticator does not exist");

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    REMOVE_AUTHENTICATOR_TYPEHASH,
                    accountIndex,
                    authenticatorAddress,
                    newOffchainSignerCommitment,
                    nonce
                )
            )
        );

        require(accountIndex == recoverAccountIndex(messageHash, signature), "Invalid account index");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");
        require(
            authenticatorAddressToAccountIndex[authenticatorAddress] == accountIndex,
            "Authenticator does not belong to account"
        );

        require(accountAuthenticators[accountIndex].length() > 1, "Account must have at least one authenticator");

        // Delete authenticator
        require(accountAuthenticators[accountIndex].remove(authenticatorAddress), "Remove failed");
        delete authenticatorAddressToAccountIndex[authenticatorAddress];

        // Update tree
        tree.update(accountIndex - 1, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        emit AuthenticatorRemoved(
            accountIndex, authenticatorAddress, oldOffchainSignerCommitment, newOffchainSignerCommitment
        );
    }

    /**
     * @dev Recovers an account.
     * @param accountIndex The index of the account.
     * @param newAuthenticatorAddress The new authenticator address.
     * @param oldOffchainSignerCommitment The old offchain signer commitment.
     * @param newOffchainSignerCommitment The new offchain signer commitment.
     * @param signature The signature.
     * @param siblingNodes The sibling nodes.
     */
    function recoverAccount(
        uint256 accountIndex,
        address newAuthenticatorAddress,
        uint256 oldOffchainSignerCommitment,
        uint256 newOffchainSignerCommitment,
        bytes memory signature,
        uint256[] calldata siblingNodes,
        uint256 nonce
    ) public {
        require(accountIndex > 0, "Account index must be greater than 0");
        require(nextAccountIndex > accountIndex, "Account does not exist");
        require(nonce == signatureNonces[accountIndex]++, "Invalid nonce");

        bytes32 messageHash = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RECOVER_ACCOUNT_TYPEHASH, accountIndex, newAuthenticatorAddress, newOffchainSignerCommitment, nonce
                )
            )
        );

        address signatureRecoveredAddress = ECDSA.recover(messageHash, signature);
        require(signatureRecoveredAddress != address(0), "Invalid signature");
        require(signatureRecoveredAddress == accountIndexToRecoveryAddress[accountIndex], "Invalid signature");
        require(authenticatorAddressToAccountIndex[newAuthenticatorAddress] == 0, "Authenticator already exists");
        require(newAuthenticatorAddress != address(0), "New authenticator address cannot be the zero address");

        // Delete all old authenticators
        address[] memory authenticators = accountAuthenticators[accountIndex].values();
        for (uint256 i = 0; i < authenticators.length; i++) {
            require(accountAuthenticators[accountIndex].remove(authenticators[i]), "Remove failed");
            delete authenticatorAddressToAccountIndex[authenticators[i]];
        }

        // Add new authenticator
        require(accountAuthenticators[accountIndex].add(newAuthenticatorAddress), "Adding authenticator failed");
        authenticatorAddressToAccountIndex[newAuthenticatorAddress] = accountIndex;

        // Update tree
        tree.update(accountIndex - 1, oldOffchainSignerCommitment, newOffchainSignerCommitment, siblingNodes);
        emit AccountRecovered(
            accountIndex, newAuthenticatorAddress, oldOffchainSignerCommitment, newOffchainSignerCommitment
        );
    }
}
