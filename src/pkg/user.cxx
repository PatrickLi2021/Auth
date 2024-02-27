#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <vector>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>

#include "../../include-shared/constants.hpp"
#include "../../include-shared/logger.hpp"
#include "../../include-shared/messages.hpp"
#include "../../include-shared/util.hpp"
#include "../../include/drivers/repl_driver.hpp"
#include "../../include/pkg/user.hpp"

/**
 * Constructor. Loads server public key.
 */
UserClient::UserClient(std::shared_ptr<NetworkDriver> network_driver,
                       std::shared_ptr<CryptoDriver> crypto_driver,
                       UserConfig user_config) {

  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
  this->user_config = user_config;

  this->cli_driver->init();

  // Load server's key
  try {
    LoadRSAPublicKey(user_config.server_verification_key_path,
                     this->RSA_server_verification_key);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading server keys; exiting");
    throw std::runtime_error("Client could not open server's keys.");
  }

  // Load keys
  try {
    LoadRSAPrivateKey(this->user_config.user_signing_key_path,
                      this->RSA_signing_key);
    LoadRSAPublicKey(this->user_config.user_verification_key_path,
                     this->RSA_verification_key);
    LoadCertificate(this->user_config.user_certificate_path, this->certificate);
    this->RSA_verification_key = this->certificate.verification_key;
    LoadPRGSeed(this->user_config.user_prg_seed_path, this->prg_seed);
  } catch (CryptoPP::FileStore::OpenErr) {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  } catch (std::runtime_error &_) {
    this->cli_driver->print_warning("Error loading keys, you may consider "
                                    "registering or logging in again!");
  }
}

/**
 * Starts repl.
 */
void UserClient::run() {
  REPLDriver<UserClient> repl = REPLDriver<UserClient>(this);
  repl.add_action("login", "login <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.add_action("register", "register <address> <port>",
                  &UserClient::HandleLoginOrRegister);
  repl.add_action("listen", "listen <port>", &UserClient::HandleUser);
  repl.add_action("connect", "connect <address> <port>",
                  &UserClient::HandleUser);
  repl.run();
}

/**
 * Diffie-Hellman key exchange with server. This function should:
 * 1) Generate a keypair, a, g^a and send it to the server.
 * 2) Receive a public value (g^a, g^b) from the server and verify its
 * signature.
 * 3) Verify that the public value the server received is g^a.
 * 4) Generate a DH shared key and generate AES and HMAC keys.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleServerKeyExchange() {
  this->cli_driver->print_left("in handlserverkeyexchange");
  // Generate key pair
  auto [dh_obj, private_value, public_value] = this->crypto_driver->DH_initialize();
  this->cli_driver->print_left("initialized keypair");
  // Send public value to server
  UserToServer_DHPublicValue_Message dh_public_msg;
  dh_public_msg.public_value = public_value;
  std::vector<unsigned char> data;
  dh_public_msg.serialize(data);
  this->network_driver->send(data);
  this->cli_driver->print_left("sent message");

  // Receive a public value from server
  this->cli_driver->print_left("received public value from server");
  ServerToUser_DHPublicValue_Message server_to_user_pub_msg;
  auto pub_val_data = network_driver->read();
  server_to_user_pub_msg.deserialize(pub_val_data);
  this->cli_driver->print_left("deserialized public value from server");
  
  // Verify its signature
  this->cli_driver->print_left("verify signature begin");
  bool verified = this->crypto_driver->RSA_verify(this->RSA_server_verification_key, concat_byteblocks(server_to_user_pub_msg.server_public_value, server_to_user_pub_msg.user_public_value), server_to_user_pub_msg.server_signature);
  if (!verified) {
    this->network_driver->disconnect();
    throw std::runtime_error("Could not verify the signature");
  }
  this->cli_driver->print_left("verify signature end");

  // Verify that public value server received is g^a
  this->cli_driver->print_left("verify public value is g^a begin");
  if (!(server_to_user_pub_msg.server_public_value == public_value)) {
    this->network_driver->disconnect();
    throw std::runtime_error("Public values don't match");
  }
  this->cli_driver->print_left("verify public value is g^a end");

  // Generate DH shared key + AES and HMAC keys
  this->cli_driver->print_left("generated keys begin");
  CryptoPP::SecByteBlock shared_key = this->crypto_driver->DH_generate_shared_key(dh_obj, private_value, public_value);
  CryptoPP::SecByteBlock aes_key = this->crypto_driver->AES_generate_key(shared_key);
  CryptoPP::SecByteBlock hmac_key = this->crypto_driver->HMAC_generate_key(shared_key);
  this->cli_driver->print_left("generated keys end");

  return std::make_pair(aes_key, hmac_key);
}

/**
 * Diffie-Hellman key exchange with another user. This function should:
 * 1) Generate a keypair, a, g^a, signs it, and sends it to the other user.
 *    Use concat_byteblock_and_cert to sign the message.
 * 2) Receive a public value from the other user and verifies its signature and
 * certificate.
 * 3) Generate a DH shared key and generate AES and HMAC keys.
 * 4) Store the other user's verification key in RSA_remote_verification_key.
 * @return tuple of AES_key, HMAC_key
 */
std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock>
UserClient::HandleUserKeyExchange() {
  // Generate key pair
  auto [dh_obj, private_value, public_value] = this->crypto_driver->DH_initialize();
  auto message = concat_byteblock_and_cert(public_value, this->certificate);
  std::string signature = this->crypto_driver->RSA_sign(this->RSA_signing_key, message);
  this->cli_driver->print_left("generated key pair here");

  // Send to other user
  UserToUser_DHPublicValue_Message dh_pub_val_msg;
  dh_pub_val_msg.public_value = public_value;
  dh_pub_val_msg.certificate = this->certificate;
  dh_pub_val_msg.user_signature = signature;
  this->cli_driver->print_left("sent keypair to other user");

  // Receive public value from other user
  UserToUser_DHPublicValue_Message other_user_msg;
  auto data = this->network_driver->read();
  other_user_msg.deserialize(data);
  this->cli_driver->print_left("received public value from other user");

  // Verify the signature and certificate
  bool user_signed = this->crypto_driver->RSA_verify(other_user_msg.certificate.verification_key, concat_byteblock_and_cert(other_user_msg.public_value, other_user_msg.certificate), other_user_msg.user_signature);
  this->cli_driver->print_left("user 4");
  if (!user_signed) {
    this->network_driver->disconnect();
    throw std::runtime_error("verification failed");
  }

  bool user_vk_signed = this->crypto_driver->RSA_verify(this->RSA_server_verification_key, concat_string_and_rsakey(other_user_msg.certificate.id, other_user_msg.certificate.verification_key), other_user_msg.certificate.server_signature);
  this->cli_driver->print_left("user 5");
  if (!user_vk_signed) {
    this->network_driver->disconnect();
    throw std::runtime_error("verification failed");
  }

  // Generate DH shared key + AES and HMAC keys
  CryptoPP::SecByteBlock shared_key = this->crypto_driver->DH_generate_shared_key(dh_obj, private_value, public_value);
  CryptoPP::SecByteBlock aes_key = this->crypto_driver->AES_generate_key(shared_key);
  CryptoPP::SecByteBlock hmac_key = this->crypto_driver->HMAC_generate_key(shared_key);

  this->RSA_remote_verification_key = other_user_msg.certificate.verification_key;

  return std::make_pair(aes_key, hmac_key);
}

/**
 * User login or register.
 */
void UserClient::HandleLoginOrRegister(std::string input) {
  // Connect to server and check if we are registering.
  std::vector<std::string> input_split = string_split(input, ' ');
  if (input_split.size() != 3) {
    this->cli_driver->print_left("invalid number of arguments.");
    return;
  }
  std::string address = input_split[1];
  int port = std::stoi(input_split[2]);
  this->network_driver->connect(address, port);
  this->DoLoginOrRegister(input_split[0]);
}

/**
 * User login or register. This function should:
 * 1) Handles key exchange with the server.
 * 2) Tells the server our ID and intent.
 * 3) Receives a salt from the server.
 * 4) Generates and sends a hashed and salted password.
 * 5) (if registering) Receives a PRG seed from the server, store in
 * this->prg_seed.
 * 6) Generates and sends a 2FA response.
 * 7) Generates a RSA keypair, and send vk to the server for signing.
 * 8) Receives and save cert in this->certificate.
 * 9) Receives and saves the keys, certificate, and prg seed.
 * Remember to store RSA keys in this->RSA_signing_key and
 * this->RSA_verification_key
 */
void UserClient::DoLoginOrRegister(std::string input) {
  // Handle key exchange with server
  this->cli_driver->print_left("In doLoginOrRegister");
  auto [aes_key, hmac_key] = HandleServerKeyExchange();
  
  // Tells server our ID and intent
  this->cli_driver->print_left("tell server id begin");
  UserToServer_IDPrompt_Message id_prompt_msg;
  this->id = this->user_config.user_username;
  id_prompt_msg.id = this->id;
  if (input == "register") {
    id_prompt_msg.new_user = true;
  } else {
    id_prompt_msg.new_user = false;
  }
  std::vector<unsigned char> data = this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &id_prompt_msg);
  this->network_driver->send(data);
  this->cli_driver->print_left("tell server id end");

  // Receives salt from server
  this->cli_driver->print_left("receive salt from server begin");
  ServerToUser_Salt_Message salt_msg;
  auto salt_msg_data = network_driver->read();
  salt_msg.deserialize(salt_msg_data);
  // TODO: Decrypt and verify (we have to explicitly call deserialize on the resulting first element of decrypt_and_verify but we do NOT have to explicity call serialize after calling encrypt_and_tag)
  auto [decrypted_salt_msg_data, salt_msg_decrypted] = this->crypto_driver->decrypt_and_verify(aes_key, hmac_key, salt_msg_data);
  if (!salt_msg_decrypted) {
    throw std::runtime_error("Could not decrypt data");
  }
  salt_msg.deserialize(decrypted_salt_msg_data);
  this->cli_driver->print_left("receive salt from server end");

  // Generates and sends a hashed and salted password
  this->cli_driver->print_left("generated and send hspw begin");
  UserToServer_HashedAndSaltedPassword_Message hs_psw;
  hs_psw.hspw = this->crypto_driver->hash(this->user_config.user_password + salt_msg.salt);
  std::vector<unsigned char> hs_psw_data = this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &hs_psw);
  this->network_driver->send(hs_psw_data);
  this->cli_driver->print_left("generated and send hspw end");

  // If registering, receive a PRG seed from server
  this->cli_driver->print_left("receive prg seed from server begin");
  ServerToUser_PRGSeed_Message prg_seed_msg;
  auto prg_seed_msg_data = this->network_driver->read();
  auto [decrypted_prg_seed_data, seed_decrypted] = this->crypto_driver->decrypt_and_verify(aes_key, hmac_key, prg_seed_msg_data);
  this->cli_driver->print_warning("user 6");
  if (!seed_decrypted) {
    throw std::runtime_error("Could not decrypt data");
  }
  prg_seed_msg.deserialize(decrypted_prg_seed_data);
  this->prg_seed = prg_seed_msg.seed;
  this->cli_driver->print_left("receive prg seed from server end");

  // Generate and send a 2FA response
  this->cli_driver->print_left("generated and send 2fa response begin");
  ServerToUser_PRGSeed_Message prg_2fa_seed_msg;
  prg_seed_msg.seed = this->prg_seed;
  std::vector<unsigned char> prg_seed_data = this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &prg_2fa_seed_msg);
  this->network_driver->send(prg_seed_data);
  this->cli_driver->print_left("generate and send 2fa response end");

  // Generates a RSA keypair, and send vk to the server for signing.
  this->cli_driver->print_left("generate rsa pair begin");
  auto [rsa_private_key, rsa_public_key] = this->crypto_driver->RSA_generate_keys();
  this->RSA_signing_key = rsa_private_key;
  UserToServer_VerificationKey_Message vk_msg;
  vk_msg.verification_key = rsa_private_key;
  std::vector<unsigned char> vk_msg_data = this->crypto_driver->encrypt_and_tag(aes_key, hmac_key, &vk_msg);
  this->network_driver->send(vk_msg_data);
  this->cli_driver->print_left("generate rsa pair end");

  // Receives and save cert in this->certificate.
  this->cli_driver->print_left("receive and save cert begin");
  ServerToUser_IssuedCertificate_Message issued_cert_msg;
  auto cert_msg_data = this->network_driver->read();
  auto [decrypted_cert_msg_data, cert_decrypted] = this->crypto_driver->decrypt_and_verify(aes_key, hmac_key, cert_msg_data);
  this->cli_driver->print_warning("3");
  if (!cert_decrypted) {
    throw std::runtime_error("Could not decrypt data");
  }
  issued_cert_msg.deserialize(decrypted_cert_msg_data);
  this->certificate = issued_cert_msg.certificate;
  this->cli_driver->print_left("receive and save cert end");

  // Receives and saves the keys, certificate, and prg seed
  this->cli_driver->print_left("receive and save keys, cert, seed begin");
  this->RSA_verification_key = issued_cert_msg.certificate.verification_key;
  SaveRSAPrivateKey(this->user_config.user_signing_key_path, this->RSA_signing_key);
  SaveRSAPublicKey(this->user_config.user_verification_key_path, this->RSA_verification_key);
  SavePRGSeed(this->user_config.user_prg_seed_path, this->prg_seed);
  SaveCertificate(this->user_config.user_certificate_path, this->certificate);
  this->cli_driver->print_left("receive and save keys, cert, seed end");
}

/**
 * Handles communicating with another user. This function
 * 1) Prompts the CLI to see if we're registering or logging in.
 * 2) Handles key exchange with the other user.
 */
void UserClient::HandleUser(std::string input) {
  // Handle if connecting or listening; parse user input.
  std::vector<std::string> args = string_split(input, ' ');
  bool isListener = args[0] == "listen";
  if (isListener) {
    if (args.size() != 2) {
      this->cli_driver->print_warning("Invalid args, usage: listen <port>");
      return;
    }
    int port = std::stoi(args[1]);
    this->network_driver->listen(port);
  } else {
    if (args.size() != 3) {
      this->cli_driver->print_warning(
          "Invalid args, usage: connect <ip> <port>");
      return;
    }
    std::string ip = args[1];
    int port = std::stoi(args[2]);
    this->network_driver->connect(ip, port);
  }

  // Exchange keys.
  auto keys = this->HandleUserKeyExchange();

  // Clear the screen
  this->cli_driver->init();
  this->cli_driver->print_success("Connected!");

  // Set up communication
  boost::thread msgListener =
      boost::thread(boost::bind(&UserClient::ReceiveThread, this, keys));
  this->SendThread(keys);
  msgListener.join();
}

/**
 * Listen for messages and print to CLI.
 */
void UserClient::ReceiveThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  while (true) {
    std::vector<unsigned char> encrypted_msg_data;
    try {
      encrypted_msg_data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      this->cli_driver->print_info("Received EOF; closing connection.");
      return;
    }
    // Check if HMAC is valid.
    auto msg_data = this->crypto_driver->decrypt_and_verify(
        keys.first, keys.second, encrypted_msg_data);
    if (!msg_data.second) {
      this->cli_driver->print_warning(
          "Invalid MAC on message; closing connection.");
      this->network_driver->disconnect();
      throw std::runtime_error("User sent message with invalid MAC.");
    }

    // Decrypt and print.
    UserToUser_Message_Message u2u_msg;
    u2u_msg.deserialize(msg_data.first);
    this->cli_driver->print_left(u2u_msg.msg);
  }
}

/**
 * Listen for stdin and send to other party.
 */
void UserClient::SendThread(
    std::pair<CryptoPP::SecByteBlock, CryptoPP::SecByteBlock> keys) {
  std::string plaintext;
  while (std::getline(std::cin, plaintext)) {
    // Read from STDIN.
    if (plaintext != "") {
      UserToUser_Message_Message u2u_msg;
      u2u_msg.msg = plaintext;

      std::vector<unsigned char> msg_data =
          this->crypto_driver->encrypt_and_tag(keys.first, keys.second,
                                               &u2u_msg);
      try {
        this->network_driver->send(msg_data);
      } catch (std::runtime_error &_) {
        this->cli_driver->print_info(
            "Other side is closed, closing connection");
        this->network_driver->disconnect();
        return;
      }
    }
    this->cli_driver->print_right(plaintext);
  }
  this->cli_driver->print_info("Received EOF from user; closing connection");
  this->network_driver->disconnect();
}
