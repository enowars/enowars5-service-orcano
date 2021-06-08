#if OC_QUANT_EXTERN

.globl set_gqr2
set_gqr2:
	mtspr 914, %r3
	blr

.globl get_gqr2
get_gqr2:
	mfspr %r3, 914
	blr

.globl load_gqr2
load_gqr2:
	psq_l %f1, 0(%r3), 1, 2
	blr

.globl store_gqr2
store_gqr2:
	psq_st %f1, 0(%r3), 1, 2
	blr

#endif