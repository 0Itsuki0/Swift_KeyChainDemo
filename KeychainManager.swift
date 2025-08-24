import SwiftUI
import Security

extension OSStatus {
    var string: String {
        let string = SecCopyErrorMessageString(self, nil)
        return string as? String ?? "code: \(self)"
    }
}

final class KeychainManager {
    
    enum KeychainError: Error {
        case saveError(OSStatus)
        case retrieveError(OSStatus)
        case failToExtractInfo
        case deleteError(OSStatus)
    }
    
    private let service = "com.itsuki.keychainDemo"
    
    // For both the create new operation and the update operation
    //
    // Marking the function async because SecItemAdd blocks the calling thread
    func saveGenericPassword(password: String, account: String) async throws {
        let passwordData = Data(password.utf8)
        
        // For a full list of attribute keys supported for a generic password item:
        // https://developer.apple.com/documentation/security/ksecclassgenericpassword
        var query = self.makePrimaryKeyDictionary(for: account)
        query[kSecValueData as String] = passwordData

        var status = SecItemAdd(query as CFDictionary, nil)
        
        // item already exists. Updating instead
        if status == errSecDuplicateItem {
            print("item exists. Updating")
            status = SecItemUpdate(query as CFDictionary, [kSecValueData: passwordData] as CFDictionary)
        }
        
        print("status: \(status.string)")
        if status != errSecSuccess {
            throw KeychainError.saveError(status)
        }

    
    }

    
    func retrieveGenericPassword(for account: String) async throws -> String {
        var query = self.makePrimaryKeyDictionary(for: account)
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        // initiate the search
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        print("status: \(status.string)")

        guard status == errSecSuccess else {
            throw KeychainError.retrieveError(status)
        }
        
        guard let existingItem = item as? [String : Any],
            let passwordData = existingItem[kSecValueData as String] as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8),
            let retrievedAccount = existingItem[kSecAttrAccount as String] as? String, // same as the account we pass in
            retrievedAccount == account
        else {
            throw KeychainError.failToExtractInfo
        }
        
        return password
        
    }
    
    
    func deleteGenericPassword(for account: String) async throws {
        let query = self.makePrimaryKeyDictionary(for: account) as CFDictionary
        let status = SecItemDelete(query)
        
        // status will be errSecItemNotFound if the item is not found for the given query
        // However, since the final goal: removing the password is achieved, it is not really an error app-wise
        print(status.string)
        if status != noErr && status != errSecItemNotFound {
            throw KeychainError.deleteError(status)
        }
    }
    
    
    private func makePrimaryKeyDictionary(for account: String) -> [String: Any] {
        return [
            // the class of the key
            kSecClass as String: kSecClassGenericPassword,
            // attributes form the composite primary keys of a generic password item
            kSecAttrService as String: self.service,
            kSecAttrAccount as String: account,
        ]
    }
    
}
