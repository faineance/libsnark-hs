//
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#define CURVE_ALT_BN128
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;


/**
 * In this example, we show a very simple zero-knowledge proving procedure
 * using the r1cs ppzksnark proof system.
 *
 * In this simple example, we show that given vector x = (1,1,1,1,1,1,1,1,1,1)
 * we know another vector a such that: inner_product(x,a)=0
 * (yes, I know this is a trivial problem, but let's just focus on the ideas)
 */


int main() {
    constexpr size_t dimension = 10; // Dimension of the vector
    using FieldT = default_r1cs_ppzksnark_pp::Fp_type; // ppT is a specification for a collection of t
    const auto one = FieldT::one(); // constant
    std::vector<FieldT> public_input{one, one, one, one, one, one, one, one, one, one}; // x = (1,1,1,1,1,1,1,1,1,1)
    std::vector<FieldT> secret_input{one, -one, one, -one, one, -one, one, -one, one,
                                     -one}; // our secret a such that <x,a> = 0


    protoboard<FieldT> pb; // The board to allocate gadgets
    pb_variable_array<FieldT> A; // The input wires (anchor) for x
    pb_variable_array<FieldT> B; // The input wires (anchor) for a
    pb_variable<FieldT> res; // The output wire (anchor)


    A.allocate(pb, dimension, "A");
    B.allocate(pb, dimension, "B");
    res.allocate(pb, "res");
    /* Connect the anchors by a inner_product computing gadget, specifying the
     * relationship for the anchors (A,B and res) to satisfy.
     * Note that this gadget introduces a lot more (to be accurate, 9) anchors
     * on the protoboard. Now there are 30 anchors in total. */
    inner_product_gadget<FieldT> compute_inner_product(pb, A, B, res, "compute_inner_product");

    /* Set the first **dimension** number of anchors as public inputs. */
    pb.set_input_sizes(dimension);
    /* Compute R1CS constraints resulted from the inner product gadget. */
    compute_inner_product.generate_r1cs_constraints();
    /* Don't forget another constraint that the output must be zero */
    generate_r1cs_equals_const_constraint(pb, pb_linear_combination<FieldT>(res), FieldT::zero());
    /* Finally, extract the resulting R1CS constraint system */
    auto cs = pb.get_constraint_system();
    /***************************************/
    /* Trusted Third Party: Key generation */
    /***************************************/
    auto keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(pb.get_constraint_system());

    /**************************************************/
    /* Prover: Fill in both inputs and generate proof */
    /**************************************************/
    for (size_t i = 0; i < dimension; i++) {
        pb.val(A[i]) = public_input[i];
        pb.val(B[i]) = secret_input[i];
    }

    /* We just set the value of the input anchors,
     * now execute this function to function the gadget and fill in the other
     * anchors */
    compute_inner_product.generate_r1cs_witness();
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    /* If res is not zero, this function will crash complaining that
     * the R1CS constraint system is not satisfied. */
    auto proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pi, ai);

    /********************************************/
    /* Verifier: fill in only the public inputs */
    /********************************************/
    for (size_t i = 0; i < dimension; i++)  // Actually, primary_input is a std::vector<FieldT>,
        pb.val(A[i]) = public_input[i];       // we can just cast or copy the public_input to get primary input,
    pi = pb.primary_input();                // but let's pretend that we don't know the implementation details

    if (r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pi, proof)) {
        cout << "Verified!" << endl;
    } else {
        cout << "Failed to verify!" << endl;
    }

    return 0;

}

bool generate_proof() {
    alt_bn128_pp::init_public_params();

}