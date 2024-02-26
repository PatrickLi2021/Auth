#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/keyloaders.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/server.hpp"
#include "../../include/pkg/user.hpp"

/**
 * Constructor
 */
ServerClient::ServerClient(ServerConfig server_config) {
  // Initialize cli driver.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->cli_driver->init();

  // Initialize database driver.
  this->db_driver = std::make_shared<DBDriver>();
  this->db_driver->open(server_config.server_db_path);
  this->db_driver->init_tables();

  // Load server keys.
  try {
    LoadRSAPrivateKey(server_config.server_signing_key_path,
                      this->RSA_signing_key);
    LoadRSAPublicKey(server_config.server_verification_key_path,
                     this->RSA_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning(
        "Could not find server keys, generating them instead.");
    CryptoDriver crypto_driver;
    auto keys = crypto_driver.RSA_generate_keys();
    this->RSA_signing_key = keys.first;
    this->RSA_verification_key = keys.second;
    SaveRSAPrivateKey(server_config.server_signing_key_path,
                      this->RSA_signing_key);
    SaveRSAPublicKey(server_config.server_verification_key_path,
                     this->RSA_verification_key);
  }
}

/**
 * Run the server on the given port. First initializes the CLI and database,
 * then starts listening for connections.
 */
void ServerClient::run(int port) {
  // Start listener thread
  std::thread listener_thread(&ServerClient::ListenForConnections, this, port);
  listener_thread.detach();

  // Start REPL
  REPLDriver<ServerClient> repl = REPLDriver<ServerClient>(this);
  repl.add_action("reset", "reset", &ServerClient::Reset);
  repl.add_action("users", "users", &ServerClient::Users);
  repl.run();
}

/**
 * Reset database
 *
 */
void ServerClient::Reset(std::string _) {
  this->cli_driver->print_info("Erasing users!");
  this->db_driver->reset_tables();
}

/**
 * Prints all usernames
 */
void ServerClient::Users(std::string _) {
  this->cli_driver->print_info("Printing users!");
  std::vector<std::string> usernames = this->db_driver->get_users();
  if (usernames.size() == 0) {
    this->cli_driver->print_info("No registered users!");
    return;
  }
  for (std::string username : usernames) {
    this->cli_driver->print_info(username);
  }
}

/**
 * @brief This is the logic for the listener thread
 */
void ServerClient::ListenForConnections(int port) {
  while (1) {
    // Create new network driver and crypto driver for this connection
    std::shared_ptr<NetworkDriver> network_driver =
        std::make_shared<NetworkDriverImpl>();
    std::shared_ptr<CryptoDriver> crypto_driver =
        std::make_shared<CryptoDriver>();
    network_driver->listen(port);
    std::thread connection_thread(&ServerClient::HandleConnection, this,
                                  network_driver, crypto_driver);
    connection_thread.detach();
  }
}

/**
 * Handle keygen and handle either logins or registrations. This function
 * should: 1) Handle key exchange with the user.
 * 2) Reads a UserToServer_IDPrompt_Message and determines whether the user is
 * attempting to login or register and calls the corresponding function.
 * 3) Disconnect the network_driver, then return true.
 */
bool ServerClient::HandleConnection(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver) {
  try {
    UserToServer_IDPrompt_Message msg;
    auto key_pair = HandleKeyExchange(network_driver, crypto_driver);
    auto data = network_driver->read();
    msg.deserialize(data);
    if (msg.new_user) {
      HandleRegister(network_driver, crypto_driver, msg.id, key_pair);
    } else {
      HandleLogin(network_driver, crypto_driver, msg.id, key_pair);
    }
    network_driver->disconnect();
    return true;
  } catch (...) {
    this->cli_driver->print_warning("Connection threw an error");
    network_driver->disconnect();
    return false;
  }
}

/**
 * Diffie-Hellman key exchange. This function should:
 * 1) Receive the user's public value
 * 2) Generate and send a signed DH public value
 * 2) Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
ServerClient::HandleKeyExchange(std::shared_ptr<NetworkDriver> network_driver,
                                std::shared_ptr<CryptoDriver> crypto_driver) {
  UserToServer_DHPublicValue_Message msg;
  auto data = network_driver->read();
  msg.deserialize(data);
  auto [dh_obj, public_value, private_value] = crypto_driver->DH_initialize();
  auto shared_key = crypto_driver->DH_generate_shared_key(dh_obj, public_value, private_value);
  auto aes_key = crypto_driver->AES_generate_key(shared_key);
  auto hmac_key = crypto_driver->HMAC_generate_key(shared_key);
  return std::make_pair(aes_key, hmac_key);
}

/**
 * Log in the given user. This function should:
 * 1) Find the user in the database.
 * 2) Send the user's salt and receive a hash of the salted password.
 * 3) Try all possible peppers until one succeeds.
 * 4) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 5) Receive the user's verification key, and sign it to create a certificate.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleLogin(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  // Find user
  UserRow user = this->db_driver->find_user(id);
  std::string user_id = user.user_id;
  // Send salt to user
  ServerToUser_Salt_Message salt_msg;
  std::vector<unsigned char> data = crypto_driver->encrypt_and_tag(keys.first, keys.second, &salt_msg);
  network_driver->send(data);
  
  // Receive hash of salted password
  UserToServer_HashedAndSaltedPassword_Message hash_and_salted_pwd_msg;
  auto received_data = network_driver->read();
  hash_and_salted_pwd_msg.deserialize(received_data);
  // Try all possible peppers
  bool found_pepper = false;
  for (int i = 0; i < 256; ++i) {
    // cast i into char, then make string struct using the char
    std::string hash_output = crypto_driver->hash(hash_and_salted_pwd_msg.hspw + std::to_string(i));
    if (hash_output == user.password_hash) {
      found_pepper = true;
      break;
    }
  }
  if (!found_pepper) {
    network_driver->disconnect();
    throw std::runtime_error("Response was not sent in time");
  }
  // Receive 2FA response
  UserToServer_PRGValue_Message prg_msg;
  auto two_fa_data = network_driver->read();
  
  crypto_driver->decrypt_and_verify(keys.first, keys.second, two_fa_data);
  prg_msg.deserialize(two_fa_data);


  bool in_time = false;
  // Check if response was generated in last 60 seconds
  CryptoPP::Integer current_time = crypto_driver->nowish();
  for (int i = 0; i < 60; ++i) {
    if (prg_msg.value == crypto_driver->prg(string_to_byteblock(user.prg_seed), integer_to_byteblock(current_time), PRG_SIZE)) {
      in_time = true;
      break;
    }
    current_time -= i;
    }
    if (!in_time) {
      network_driver->disconnect();
      throw std::runtime_error("Response was not sent in time");
    }
      // Receive user's verification key
      UserToServer_VerificationKey_Message vk_msg;
      auto vk_msg_data = network_driver->read();
      auto [decrypted_data, decrypted] = crypto_driver->decrypt_and_verify(keys.first, keys.second, vk_msg_data);
      if (!decrypted) {
        network_driver->disconnect();
        throw std::runtime_error("Message could not be decrypted");
      }
      vk_msg.deserialize(decrypted_data);
      
      // Sign and create certificate
      auto [private_key, public_key] = crypto_driver->RSA_generate_keys();
      std::string server_sig = crypto_driver->RSA_sign(private_key, concat_string_and_rsakey(user.user_id, vk_msg.verification_key));

      // Send certificate back to user
      ServerToUser_IssuedCertificate_Message issued_cert_msg;
      Certificate_Message certificate;
      certificate.id = user.user_id;
      certificate.verification_key = vk_msg.verification_key;
      certificate.server_signature = server_sig;
      std::vector<unsigned char> cert_data = crypto_driver->encrypt_and_tag(keys.first, keys.second, &issued_cert_msg);
      issued_cert_msg.certificate = certificate;
      network_driver->send(cert_data);
    }

/**
 * Register the given user. This function should:
 * 1) Confirm that the user in not the database.
 * 2) Generate and send a salt and receives a hash of the salted password.
 * 3) Generate a pepper and store a second hash of the response + pepper.
 * 4) Generate and sends a PRG seed to the user
 * 4) Receive a 2FA response and verify it was generated in the last 60 seconds.
 * 5) Receive the user's verification key, and sign it to create a certificate.
 * 6) Store the user in the database.
 * @param id id of the user logging in
 * @param keys tuple of AES_key, HMAC_key corresponding to this session
 */
void ServerClient::HandleRegister(
    std::shared_ptr<NetworkDriver> network_driver,
    std::shared_ptr<CryptoDriver> crypto_driver, std::string id,
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  // Confirm user is not in database
  UserRow user = this->db_driver->find_user(id);
  if (!(user.user_id == "")) { 
    throw std::runtime_error("User already exists");
  }
  // Create a new user
  UserRow new_user;
  new_user.user_id = id;
  
  // Generate and send salt
  CryptoPP::SecByteBlock salt = crypto_driver->png(SALT_SIZE);
  ServerToUser_Salt_Message salt_msg;
  salt_msg.salt = byteblock_to_string(salt);
  std::vector<unsigned char> send_data = crypto_driver->encrypt_and_tag(keys.first, keys.second, &salt_msg);
  network_driver->send(send_data);

  // Receive hash of salted password
  UserToServer_HashedAndSaltedPassword_Message hash_and_salted_pwd;
  auto data = network_driver->read();
  auto [decrypted_data, decrypted] = crypto_driver->decrypt_and_verify(keys.first, keys.second, data);
  if (!decrypted) {
    network_driver->disconnect();
    throw std::runtime_error("Message could not be decrypted");
  }
  hash_and_salted_pwd.deserialize(data);
  new_user.password_salt = hash_and_salted_pwd.hspw;

  // Generate pepper and stored second hash
  CryptoPP::SecByteBlock pepper = crypto_driver->png(PEPPER_SIZE);
  std::string hash_response = crypto_driver->hash(hash_and_salted_pwd.hspw + byteblock_to_string(pepper));
  new_user.password_hash = hash_response;

  // Generates and sends PRG seed to user
  ServerToUser_PRGSeed_Message prg_seed_msg;
  CryptoPP::SecByteBlock user_seed = crypto_driver->png(PRG_SIZE);
  prg_seed_msg.seed = user_seed;
  std::vector<unsigned char> prg_data = crypto_driver->encrypt_and_tag(keys.first, keys.second, &prg_seed_msg);
  network_driver->send(prg_data);
  
  // Receive 2FA response
  UserToServer_PRGValue_Message prg_msg;
  auto prg_msg_data = network_driver->read();
  auto [decrypted_prg_msg_data, prg_msg_decrypted] = crypto_driver->decrypt_and_verify(keys.first, keys.second, prg_msg_data);
  if (!prg_msg_decrypted) {
    network_driver->disconnect();
    throw std::runtime_error("Message could not be decrypted");
  }
  prg_msg.deserialize(decrypted_prg_msg_data);

  // Check to see if it was generated in the last 60 seconds
  bool in_time = false;
  for (int i = 0; i < 60; ++i) {
    if (prg_msg.value == crypto_driver->prg(string_to_byteblock(new_user.prg_seed), integer_to_byteblock(crypto_driver->nowish() - i), PRG_SIZE)) {
      in_time = true;
      break;
    }
  }
  if (in_time) {
    // Receive user's verification key
    UserToServer_VerificationKey_Message vk_msg;
    auto data = network_driver->read();
    auto [decrypted_data, decrypted] = crypto_driver->decrypt_and_verify(keys.first, keys.second, data);
    if (!decrypted) {
      network_driver->disconnect();
      throw std::runtime_error("Message could not be decrypted");
    }
    vk_msg.deserialize(data);
    
    // Sign and create certificate
    auto [private_key, public_key] = crypto_driver->RSA_generate_keys();
    std::string server_sig = crypto_driver->RSA_sign(private_key, concat_string_and_rsakey(new_user.user_id, vk_msg.verification_key));

    // Send certificate back to user
    ServerToUser_IssuedCertificate_Message issued_cert_msg;
    Certificate_Message certificate;
    certificate.id = new_user.user_id;
    certificate.verification_key = vk_msg.verification_key;
    certificate.server_signature = server_sig;
    std::vector<unsigned char> cert_msg_data = crypto_driver->encrypt_and_tag(keys.first, keys.second, &issued_cert_msg);
    issued_cert_msg.certificate = certificate;
    network_driver->send(cert_msg_data);
    
    this->db_driver->insert_user(new_user);
  }
  network_driver->disconnect();
}