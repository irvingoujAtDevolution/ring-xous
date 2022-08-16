/*
fn p256_elem_add_test() {
    elem_add_test(
        &p256::PUBLIC_SCALAR_OPS,
        test_file!("ops/p256_elem_sum_tests.txt"),
    );
}

fn elem_add_test(ops: &PublicScalarOps, test_file: test::File) {
    test::run(test_file, |section, test_case| {
        assert_eq!(section, "");

        let cops = ops.public_key_ops.common;
        let a = consume_elem(cops, test_case, "a");
        let b = consume_elem(cops, test_case, "b");
        let expected_sum = consume_elem(cops, test_case, "r");

        let mut actual_sum = a;
        ops.public_key_ops.common.elem_add(&mut actual_sum, &b);
        assert_limbs_are_equal(cops, &actual_sum.limbs, &expected_sum.limbs);

        let mut actual_sum = b;
        ops.public_key_ops.common.elem_add(&mut actual_sum, &a);
        assert_limbs_are_equal(cops, &actual_sum.limbs, &expected_sum.limbs);

        Ok(())
    })
}
//  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
*/