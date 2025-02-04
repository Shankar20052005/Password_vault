// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PasswordVault {
    struct Credential {
        string username;
        string encryptedPassword;
    }

    // Owner of the contract (admin)
    address private owner;
    
    // Mapping: User address → Platform → Credentials (username + encrypted password)
    mapping(address => mapping(string => Credential)) private vaults;
    
    // Mapping: Admins (for role-based access control)
    mapping(address => bool) private admins;

    // Events for logging actions
    event PasswordStored(address indexed user, string platform);
    event CredentialDeleted(address indexed user, string platform);
    event AdminAdded(address indexed admin);
    event AdminRemoved(address indexed admin);

    // Modifier: Only contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner can call this function");
        _;
    }

    // Modifier: Only owner or admin can call
    modifier onlyAdmin() {
        require(admins[msg.sender] || msg.sender == owner, "Only admins or owner can call this function");
        _;
    }

    // Constructor: Sets the contract deployer as owner
    constructor() {
        owner = msg.sender;
    }

    // Function to add an admin (Only owner can add)
    function addAdmin(address _admin) public onlyOwner {
        admins[_admin] = true;
        emit AdminAdded(_admin);
    }

    // Function to remove an admin (Only owner can remove)
    function removeAdmin(address _admin) public onlyOwner {
        admins[_admin] = false;
        emit AdminRemoved(_admin);
    }

    // Function to store credentials securely
    function storeCredential(
        string memory platform,
        string memory username,
        string memory encryptedPassword
    ) public {
        vaults[msg.sender][platform] = Credential(username, encryptedPassword);
        emit PasswordStored(msg.sender, platform);
    }

    // Function to retrieve credentials securely
    function retrieveCredential(string memory platform) public view returns (string memory, string memory) {
        require(bytes(vaults[msg.sender][platform].username).length > 0, "No credentials found for this platform");

        Credential memory credential = vaults[msg.sender][platform];
        return (credential.username, credential.encryptedPassword);
    }

    // Function to delete stored credentials (Only owner or admin can delete)
    function deleteCredential(string memory platform) public onlyAdmin {
        require(bytes(vaults[msg.sender][platform].username).length > 0, "No credentials found for this platform");

        delete vaults[msg.sender][platform]; // Secure deletion of credentials
        emit CredentialDeleted(msg.sender, platform);
    }
}
