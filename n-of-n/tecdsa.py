from Crypto.Hash import SHA256
from phe import paillier
from typing import List

from utils import add, add_ec, multiply, rand, egcd, verify_ecdsa_signature
from setup import ECDSASetup
from network import Network, Client

class ThresholdSignature(Network):
    clients: List[Client]

    def __init__(self, N, C, setup=None, debug=False):

        self.debug = debug
        if type(setup) == ECDSASetup:
            self.ecdsa = setup.generate_ecdsa_setup()
            self.setup = ECDSASetup
            super().__init__(N, self.ecdsa.q, self.ecdsa.h)
        else:
            raise TypeError("Invalid type provided. "
                            "Please use 'ECDSASetup' type."
                            )

        # Generate public and private keys for the paillier homomorphic encryption scheme
        for i in range(C):
            pub_key, priv_key = paillier.generate_paillier_keypair()
            self.clients[i].he_private_key = priv_key
            for node in self.nodes:
                node.he_public_keys[i] = pub_key
            for client in self.clients:
                client.he_public_keys[i] = pub_key


    def get_lambda(self, labels: list[str]) -> None:
        n = len(labels)
        h = self.h
        q = self.q
        q_minus_one = q - 1
        for l in range(n):
            # Locally generate lambda
            alpha = rand(q_minus_one)
            h_alpha = pow(h, alpha, q)

            self.share(alpha, q_minus_one, labels[l]+"_lambda_sh_exp")
            self.share(h_alpha, q, labels[l]+"_lambda_sh_base")

    def rss_protocol(self, size: int, label: str) -> None:
        # Round 1
        for node in self.nodes:
            # Step 1: locally generate random secret
            random_element = rand(size)
            # Step 2: share random secret with all nodes
            self.share(random_element, size, label+"sh_node_"+str(node.id))
        # All local
        for node in self.nodes:
            # DB management
            list_of_shares = [
                node.get_share(label + "sh_node_" + str(other_node.id))
                for other_node in self.nodes
            ]
            # Step 3: add locally all shares
            random_sum = add(list_of_shares, size)
            # DB management
            sh_label = label+"_sh_exp"
            node.set_share(random_sum, sh_label)
            if not self.debug:
                [node.delete_share(label + "sh_node_" + str(other_node.id))
                 for other_node in self.nodes]

    def pow_share_protocol(self, base_type: str, get_label: str, save_label: str) -> None:
        if base_type not in ["exp", "base"]:
            raise ValueError("{} is not one of the specified base types.\
                              Please choose one of the following:\n \
                             ['exp', 'base']".format(base_type))

        prime = self.q if base_type == "exp" else self.dsa.p

        # Round 1
        for node in self.nodes:
            # DB management
            exponent = node.get_share(get_label+"_sh_"+base_type)
            # Step 1: compute base^share
            if base_type == "exp":
                h_exp = pow(self.h, exponent, prime)
            else:
                h_exp = pow(self.dsa.g, exponent, prime)
            # Step 2: Broadcast base^share to nodes
            self.broadcast(h_exp, "pow_share_node_"+str(node.id))

        # All local
        for node in self.nodes:
            # DB management
            base_exps = [
                node.get_open("pow_share_node_"+str(other_node.id))
                for other_node in self.nodes
            ]
            # Step 3: multiply locally all powers of shares
            val = multiply(base_exps, prime)
            # DB management
            node.set_open(val, save_label)
            if not self.debug:
                [node.delete_open("pow_share_node_"+str(other_node.id))
                 for other_node in self.nodes]

    def ec_pow_share_protocol(self, get_label: str, save_label: str) -> None:
        # Round 1
        for node in self.nodes:
            # DB management
            scalar_sh = node.get_share(get_label+"_sh_base")
            # Step 1:
            sh_G = scalar_sh * self.ecdsa.G
            # Step 2:
            self.broadcast(sh_G, "ec_pow_share_node_"+str(node.id))

        # All local
        for node in self.nodes:
            # DB management
            base_exps = [
                node.get_open("ec_pow_share_node_"+str(other_node.id))
                for other_node in self.nodes
            ]
            # Step 3: add locally all point shares
            val = add_ec(base_exps)
            # DB management
            node.set_open(val, save_label)
            if not self.debug:
                [node.delete_open("ec_pow_share_node_"+str(other_node.id))
                 for other_node in self.nodes]

    def subtract_exp_shares_local(self, label_a: str, label_b: str, label_r: str) -> None:
        q_minus_one = self.q - 1

        for node in self.nodes:
            # DB management
            share_a = node.get_share(label_a+"_sh_exp")
            share_b = node.get_share(label_b+"_sh_exp")
            # Local operation: subtraction
            share_r = (share_a - share_b) % q_minus_one
            # DB management
            label = label_r+"_sh_exp"
            node.set_share(share_r, label)

    def pow_local(self, label_base: str, label_exponent: str, label_result: str) -> None:
        for node in self.nodes:
            # DB management
            base = node.get_open(label_base)
            exponent = node.get_open(label_exponent)
            # Local operation: power
            result = pow(base, exponent, self.dsa.p)
            # DB management
            node.set_open(result, label_result)

    def key_agreement_protocol(self, label: str, delete=True) -> None:
        q_minus_one = self.q - 1

        # Round 1
        # Step 1:
        random_label = "random"
        self.rss_protocol(q_minus_one, random_label)

        # Round 2
        # Step 2:
        random_minus_label = random_label + "_minus_" + label
        self.subtract_exp_shares_local(random_label, label + "_lambda", random_minus_label)
        base_type_exp = "exp"
        self.pow_share_protocol(base_type_exp, random_minus_label, label + "_sk")

       
        # Step 3:
        self.ec_pow_share_protocol(label + "_lambda", label + "_pre_pk")
        # Step 4:
        self.ec_mult_local(label + "_pre_pk", label + "_sk", label + "_pk")

        # DB management
        ## Option only for testing purposes
        if delete:
            [node.delete_share(random_minus_label+"_sh_exp") for node in self.nodes]
            [node.delete_share(random_label+"_sh_exp") for node in self.nodes]
            [node.delete_open(label + "_pre_pk") for node in self.nodes]

    def ec_mult_local(self, label_ec_point: str, label_scalar: str, label_result: str) -> None:
        for node in self.nodes:
            # DB management
            ec_point = node.get_open(label_ec_point)
            scalar = node.get_open(label_scalar)
            # Local operation: mult
            result = scalar * ec_point
            # DB management
            node.set_open(result, label_result)

    def encrypt_and_delete_exp_sh_local(self, label: str, client_id: int) -> None:
        for node in self.nodes:
            # DB management
            clear_share = node.get_share(label+"_lambda_sh_exp")
            # Local operation:
            ## Encrypt share
            enc_sh_val = node.he_public_keys[client_id - 1].encrypt(clear_share)
            ## Delete lambda pair
            node.delete_share(label+"_lambda_sh_exp")
            node.delete_share(label+"_lambda_sh_base")
            # DB management
            sh_label = label+"_enc_sh_exp"
            node.set_share(enc_sh_val, sh_label)

    def send_public_key_to_client(self, label: str, client: Client) -> None:
        all_y = [node.get_open(label+"_pk") for node in self.nodes]
        # Check if all elements in the list are equal
        are_all_equal = all(y == all_y[0] for y in all_y)
        if are_all_equal:
            client.set_open(all_y[0], label+"_pk")
        else:
            raise PublicKeyDisagreement("Abort.")

    def distributed_key_generation_protocol(self, client_id: int, label=None) -> None:
        # Check there exist a client
        client = next((client for client in self.clients if client.id == client_id), None)
        if client == None:
            raise TypeError(f"Client with id {client_id} is not part of the network.")
        label = str(client_id)+"th_client_"+str(label) if label else str(client_id)+"th_client_"+"x"
        delete = not self.debug
        # Step 1
        self.get_lambda([label])

        # Step 2
        self.key_agreement_protocol(label, delete=delete)

        # Step 3
        self.send_public_key_to_client(label, client)

        # Step 4
        self.encrypt_and_delete_exp_sh_local(label, client_id)


    def compute_r_local(self, label: str, client: Client, delete=True) -> None:
        for node in self.nodes:
            # DB management
            R = node.get_open(label + "_pk")
            # Local operation
            r = int(R.x)
            # DB management
            node.set_open(r, label + "_r")
            node.delete_open(label + "_pk")
        client.set_open(r, label + "_r")

    def invert_masked_factor_local(self, label) -> None:
        for node in self.nodes:
            # DB management
            masked_factor = node.get_open(label+"_sk")
            share = node.get_share(label+"_lambda_sh_exp")
            # Local operation
            ## Invert masked factor
            inv_masked_factor = egcd(masked_factor, self.q)
            ## Invert share
            inv_share = -share % (self.q - 1)
            # DB management
            node.set_open(inv_masked_factor, label+"_inv_sk")
            sh_inv_label = label+"_inv_lambda_sh_exp"
            node.set_share(inv_share, sh_inv_label)

    def step_4_encrypt_elements(
            self, 
            label_lambda_1: str, 
            label_lambda_2: str, 
            labdel_lambda_k_inv: str, 
            save_label_m: str,
            save_label_gap: str,
            save_label_lambda_1: str,
            save_label_lambda_2: str,
            client_id: int
        ) -> None:
        
        q_minus_one = self.q - 1
        for node in self.nodes:
            # DB management
            sh_lambda_1_exp = node.get_share(label_lambda_1 +"_sh_exp")
            sh_lambda_2_exp = node.get_share(label_lambda_2 +"_sh_exp")
            sh_lambda_k_inv = node.get_share(labdel_lambda_k_inv +"_sh_exp")
            sh_lambda_1_base = node.get_share(label_lambda_1 +"_sh_base")
            sh_lambda_2_base = node.get_share(label_lambda_2 +"_sh_base")
            enc_lambda_sk = node.get_share(str(client_id)+"th_client_x_enc_sh_exp")
            # Local operation
            ## 4(a)
            sh_m = (sh_lambda_1_exp - sh_lambda_k_inv) % q_minus_one
            enc_sh_m = node.he_public_keys[client_id - 1].encrypt(sh_m)
            ## 4(b)
            sh_int_gap = (sh_lambda_k_inv - sh_lambda_2_exp) % q_minus_one
            enc_sh_int_gap = node.he_public_keys[client_id - 1].encrypt(sh_int_gap)
            enc_sh_gap = enc_sh_int_gap + enc_lambda_sk
            ## 4(c)
            enc_sh_lambda_1_base = node.he_public_keys[client_id - 1].encrypt(sh_lambda_1_base)
            enc_sh_lambda_2_base= node.he_public_keys[client_id - 1].encrypt(sh_lambda_2_base)
            # DB management
            node.set_share(enc_sh_m, save_label_m+"_sh_exp")
            node.set_share(enc_sh_gap, save_label_gap+"_sh_exp")
            node.set_share(enc_sh_lambda_1_base, save_label_lambda_1+"_sh_base")
            node.set_share(enc_sh_lambda_2_base, save_label_lambda_2+"_sh_base")


    def delete_shares(self, list: List) -> None:
        for node in self.nodes:
            for element in list:
                node.delete_share(element)
    


    def decrypt_and_reconstruct_local(self, get_label: str, save_label: str, client: Client) -> None:
        # DB management
        enc_sh_per_node = [client.get_share(get_label+"_sh_exp_node_"+str(node.id)) for node in self.nodes]
        # Local operation
        ## Decrypt
        dec_sh_per_node = [client.he_private_key.decrypt(enc_sh) for enc_sh in enc_sh_per_node]
        q_minus_one = self.q - 1
        ## Reconstruct and take the symmetric value
        dec_val = add(dec_sh_per_node, q_minus_one)
        # DB management
        dec_label = save_label + "_exp"
        client.set_share(dec_val, dec_label)
        [client.delete_share(get_label+"_sh_exp_node_"+str(node.id)) for node in self.nodes] if not self.debug else None

   
    def ts_prep_protocol(self, client_id):
        # Check there exist a client
        client = next((client for client in self.clients if client.id == client_id), None)
        if client == None:
            raise TypeError(f"Client with id {client_id} is not part of the network.")
        # Check there exist client public key triple (<x>, y, Enc([\lambda_x]))
        try: 
            for node in self.nodes:
                node.get_open(str(client_id)+"th_client_x_sk")
                node.get_open(str(client_id)+"th_client_x_pk")
                node.get_share(str(client_id)+"th_client_x_enc_sh_exp")
        except KeyError:
            print(f"Public key triple (<x>, y, Enc([\lambda_x])) from DKG is not complete for client {client_id}. Generate it first using 'distributed_key_generation_protocol({client_id})'")
        
        # Signers preprocessing
        # Step 1
        label_k = str(client_id)+"th_client_k"    
        label_lambda_1 = str(client_id)+"th_client_lambda_1"   
        label_lambda_2 = str(client_id)+"th_client_lambda_2"   
        self.get_lambda([label_k, label_lambda_1, label_lambda_2])
        # Step 2
        self.key_agreement_protocol(label_k)
        # Step 3(a): set r
        self.compute_r_local(label_k, client)
        # Step 3(b): invert k
        self.invert_masked_factor_local(label_k)
        # Step 4: encrypt 
        self.step_4_encrypt_elements(
            label_lambda_1 + "_lambda", 
            label_lambda_2 + "_lambda", 
            label_k + "_inv_lambda", 
            str(client_id)+"th_client_m_lambda_enc",
            str(client_id)+"th_client_gap_lambda_enc",
            str(client_id)+"th_client_lambda_1_enc" ,
            str(client_id)+"th_client_lambda_2_enc" ,
            client_id)
        # Step 5: delete
        self.delete_shares([
            str(client_id)+"th_client_k_lambda_sh_exp",
            str(client_id)+"th_client_k_lambda_sh_base",
            str(client_id)+"th_client_lambda_1_lambda_sh_exp",
            str(client_id)+"th_client_lambda_1_lambda_sh_base",
            str(client_id)+"th_client_lambda_2_lambda_sh_exp",
            str(client_id)+"th_client_lambda_2_lambda_sh_base",
            str(client_id)+"th_client_k_inv_lambda_sh_exp",
        ])

        # Client preprocessing

        # Step 6: send encryption
        label_gap = "gap_lambda"
        label_send_gap = str(client_id)+"th_client_"+ label_gap +"_enc"
        label_m = "m_lambda"
        label_send_m = str(client_id)+"th_client_"+ label_m +"_enc"
        type_share = "exp"
        self.send(type_share, label_send_gap, client, delete=True)
        self.send(type_share, label_send_m, client, delete=True)
        # Step 7: client decrypts and reconstructs
        self.decrypt_and_reconstruct_local(label_send_gap, label_gap, client)
        self.decrypt_and_reconstruct_local(label_send_m, label_m, client)




    def broadcast_masked_message_digest(self, message: str, client: Client) -> None:
        # DB management
        m_lambda_exp = client.get_share("m_lambda_exp")
        gap_lambda_exp = client.get_share("gap_lambda_exp")
        # Local operation
        ## Compute message
        message_digest = SHA256.new(data=message.encode("utf-8"))
        m = int(message_digest.hexdigest(), 16) % self.q
        ## Compute gap particle
        minus_m_plus_gap = (-(m_lambda_exp + gap_lambda_exp)) % (self.q - 1)
        gap_particle = (m * pow(self.h, minus_m_plus_gap, self.q)) % self.q
        # Broadcast
        self.broadcast(gap_particle, str(client.id)+"th_client_gap_particle_m")

    def sign_local(self, client_id: int, delete=True):
        q = self.q
        
        for node in self.nodes:
            # DB management
            enc_sh_lambda_1 = node.get_share(str(client_id)+"th_client_lambda_1_enc_sh_base")
            enc_sh_lambda_2 = node.get_share(str(client_id)+"th_client_lambda_2_enc_sh_base")
            p_k_inv = node.get_open(str(client_id)+"th_client_k_inv_sk")
            p_x = node.get_open(str(client_id)+"th_client_x_sk")
            p_r = node.get_open(str(client_id)+"th_client_k_r")
            p_gap_m = node.get_open(str(client_id)+"th_client_gap_particle_m")
            # Local operation
            scalar_k_m = (p_k_inv * p_gap_m) % q
            scalar_k_r_x = (((p_k_inv * p_r) % q) * p_x) % q
            enc_sh_s_gap = enc_sh_lambda_1 * scalar_k_m + enc_sh_lambda_2 * scalar_k_r_x
            # DB management
            node.set_share(enc_sh_s_gap, str(client_id)+"th_client_enc_signature_sh_base")
            if delete:
                node.delete_open(str(client_id)+"th_client_k_sk")

    def reconstruct_and_verify_sig(self, message: str, get_label: str, client: Client, delete=True):
        q = self.q
        G = self.ecdsa.G
        
        # DB management
        gap_lambda_exp = client.get_share("gap_lambda_exp")
        y = client.get_open(str(client.id)+"th_client_x_pk")
        r = client.get_open(str(client.id)+"th_client_k_r")
        s_h_gap = client.get_share(get_label)
        # Compute signature
        s = (s_h_gap * pow(self.h, gap_lambda_exp, self.q)) % self.q
        # Verify signature
        verify_ecdsa_signature(message, r, s, y, q, G)
        # DB management
        signature_label = str(client.id)+"th_client_s"
        client.set_open(s, signature_label)
        message_label = str(client.id)+"th_client_message"
        client.set_open(message, message_label)

    def decrypt_reconstruct_unmask_verify_sig_local(self, message: str, get_label: str, client: Client, delete=True):
        q = self.q
        G = self.ecdsa.G


        # DB management
        enc_sh_per_node = [client.get_share(str(client.id)+"th_client_"+get_label+"_sh_base_node_"+str(node.id)) for node in self.nodes]
        gap_lambda_exp = client.get_share("gap_lambda_exp")
        y = client.get_open(str(client.id)+"th_client_x_pk")
        r = client.get_open(str(client.id)+"th_client_k_r")

        # Local operation
        ## Decrypt
        dec_sh_per_node = [client.he_private_key.decrypt(enc_sh) for enc_sh in enc_sh_per_node]
        q_minus_one = self.q - 1
        ## Reconstruct
        s_h_gap = add(dec_sh_per_node, q)
        ## Unmask
        s = (s_h_gap * pow(self.h, gap_lambda_exp, q)) % q
        # Verify signature
        verify_ecdsa_signature(message, r, s, y, q, G)
        # DB management
        signature_label = str(client.id)+"th_client_s"
        client.set_open(s, signature_label)
        message_label = str(client.id)+"th_client_message"
        client.set_open(message, message_label)

        

    def ts_online_protocol(self, message: str, client_id: int) -> None:
        # Check there exist a client
        client = next((client for client in self.clients if client.id == client_id), None)
        if client == None:
            raise TypeError(f"Client with id {client_id} is not part of the network.")
        # Check there 'ts_prep_protocol' was run
        try:
            for node in self.nodes:
                node.get_open(str(client_id)+"th_client_k_inv_sk")
                node.get_open(str(client_id)+"th_client_k_r")
                client.get_share("gap_lambda_exp")
                client.get_share("m_lambda_exp")
        except KeyError:
            print(f"The preprocessing phase was not run for client {client_id}.")
        

        # Step 8: compute digest, mask it, include gap and broadcast the result to all nodes
        self.broadcast_masked_message_digest(message, client)
 
        # Step 9a: all nodes compute locally the shares corresponding to clients 
        delete = not self.debug
        self.sign_local(client_id, delete=delete)

        # Step 9b: send encryption
        label_enc_sig = "enc_signature"
        label_send_enc_sig = str(client_id)+"th_client_" + label_enc_sig
        type_share = "base"
        self.send(type_share, label_send_enc_sig, client, delete=True)
        # Step 10: client decrypts, reconstructs, unmasks and verifies signature
        self.decrypt_reconstruct_unmask_verify_sig_local(message, label_enc_sig, client)

    def print_signature(self, client_id: int) -> None:

        # Check there exist a client
        client = next((client for client in self.clients if client.id == client_id), None)
        if client == None:
            raise TypeError(f"Client with id {client_id} is not part of the network.")
        # Check there exist client public key triple (<x>, y, Enc([\lambda_x]))
        try: 
            r = client.get_open(str(client.id)+"th_client_k_r")
            s = client.get_open(str(client.id)+"th_client_s")
            m = client.get_open(str(client.id)+"th_client_message")
        except KeyError:
            print(f"Signature not generated for client {client_id}.'")

        print(f"    Client(id={client_id},")
        print(f"      r={r},")
        print(f"      s={s},")
        print(f"      m={m},\n    )")


    def retrieve_signature(self, client_id: int) -> (int, int, str):

        # Check there exist a client
        client = next((client for client in self.clients if client.id == client_id), None)
        if client == None:
            raise TypeError(f"Client with id {client_id} is not part of the network.")
        # Check there exist client public key triple (<x>, y, Enc([\lambda_x]))
        try: 
            r = client.get_open(str(client.id)+"th_client_k_r")
            s = client.get_open(str(client.id)+"th_client_s")
            m = client.get_open(str(client.id)+"th_client_message")
        except KeyError:
            print(f"Signature not generated for client {client_id}.'")

        return r, s, m


class PublicKeyDisagreement(Exception):
    def __init__(self, message):
        self.message = f"Public keys are not consistent. {message}"
        super().__init__(self.message)



if __name__ == '__main__':
    N = 5; C = 1
    
    ECDSASetup.supported_curves()
    
    ecdsa_setup = ECDSASetup(curve="P-256")
    ecnil = ThresholdSignature(N, C, setup=ecdsa_setup)
    
    ecnil_debug = ThresholdSignature(N, C, setup=ecdsa_setup, debug=True)
    
    client_id = 1
    
    ecnil.distributed_key_generation_protocol(client_id)
    
    ecnil.ts_prep_protocol(client_id)
    
    message = "Very secret message."
    
    ecnil.ts_online_protocol(message, client_id)
    
    r, s, m = ecnil.retrieve_signature(client_id)
    # Public parameters (client's public key, ecdsa setup)
    Y = ecnil.clients[client_id - 1].get_open(str(client_id)+"th_client_x_pk")
    q = ecnil.q
    G = ecnil.ecdsa.G
    # Verify
    verify_ecdsa_signature(message, r, s, Y, q, G)
    
    ecnil_debug.print()