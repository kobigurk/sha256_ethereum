#include <iostream>

#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/depends/libff/libff/common/default_types/ec_pp.hpp"
#include "libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp"


#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/hash_io.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_components.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

using namespace libsnark;
using namespace libff;

using std::vector;

typedef libff::Fr<libff::default_ec_pp> FieldT;

pb_variable_array<FieldT> from_bits(std::vector<bool> bits, pb_variable<FieldT>& ZERO) {
    pb_variable_array<FieldT> acc;

		for (size_t i = 0; i < bits.size(); i++) {
			bool bit = bits[i];
			acc.emplace_back(bit ? ONE : ZERO);
		}

    return acc;
}

class ethereum_sha256 : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;

public:
    ethereum_sha256(
        protoboard<FieldT> &pb,
        pb_variable<FieldT>& ZERO,
        pb_variable_array<FieldT>& a,
        pb_variable_array<FieldT>& b,
        std::shared_ptr<digest_variable<FieldT>> result
    ) : gadget<FieldT>(pb, "ethereum_sha256") {

        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, "intermediate"));

        // final padding
        pb_variable_array<FieldT> length_padding =
            from_bits({
                // padding
                1,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,

                // length of message (512 bits)
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,0,0,
                0,0,0,0,0,0,1,0,
                0,0,0,0,0,0,0,0
            }, ZERO);

        block1.reset(new block_variable<FieldT>(pb, {
            a,
            b
        }, "block1"));

        block2.reset(new block_variable<FieldT>(pb, {
            length_padding
        }, "block2"));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
        "hasher1"));

        pb_linear_combination_array<FieldT> IV2(intermediate_hash->bits);

        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV2,
            block2->bits,
            *result,
        "hasher2"));
    }

    void generate_r1cs_constraints() {
        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
    }
};

vector<unsigned long> bit_list_to_ints(vector<bool> bit_list, const size_t wordsize) {
  vector<unsigned long> res;
	size_t iterations = bit_list.size()/wordsize+1;
  for (size_t i = 0; i < iterations; ++i) {
      unsigned long current = 0;
      for (size_t j = 0; j < wordsize; ++j) {
					if (bit_list.size() == (i*wordsize+j)) break;
          current += (bit_list[i*wordsize+j] * (1ul<<(wordsize-1-j)));
      }
      res.push_back(current);
  }
  return res;
}

int main() {
  default_ec_pp::init_public_params();

  protoboard<FieldT> pb;

  pb_variable<FieldT> ZERO;
  ZERO.allocate(pb, "ZERO");
	pb.val(ZERO) = 0;

  /*
  std::cout << "SETUP: " << std::endl;
  std::cout << pb.val(ZERO).as_ulong() << std::endl;
  std::cout << pb.val(ONE).as_ulong() << std::endl;
  std::cout << std::endl;
  */

  pb_variable_array<FieldT> a;
	a.allocate(pb, 256, "a");
  for (size_t i = 0; i < a.size(); i++) {
    pb.val(a[i]) = 0;
  }
  pb.val(a[a.size() - 1]) = 1;
  pb.val(a[a.size() - 3]) = 1;


  pb_variable_array<FieldT> b;
	b.allocate(pb, 256, "b");
  for (size_t i = 0; i < b.size(); i++) {
    pb.val(b[i]) = 0;
  }

  std::shared_ptr<digest_variable<FieldT>> result;
  result.reset(new digest_variable<FieldT>(pb, 256, "result"));

  ethereum_sha256 g(pb, ZERO, a, b, result);
	g.generate_r1cs_constraints();
	g.generate_r1cs_witness();

  //std::cout << pb.is_satisfied() << std::endl;


  auto ints = bit_list_to_ints(result->get_digest(), 32);
  for (size_t i = 0; i < ints.size(); i++) {
    std::cout << std::hex << ints[i] << std::endl;
  }

  auto digest = result->get_digest();
  for (size_t i = 0; i < digest.size(); i++) {
    //std::cout << (digest[i] ? 1 : 0) << ",";
  }

  std::cout << std::dec << pb.get_constraint_system().num_constraints() << std::endl;


  return 0;
}
