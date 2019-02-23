dirs= key pcr state nv vtcm_hub vtcm_utils vtcm_store vtcm_switch vtcm_port vtcm_input vtcm_auto auth vtcm_channel vtcm_tcp_channel tpm_init_channel vtcm_tcp_client vtcm_drv_client
all:
	$(foreach N,$(dirs),make -C $(N) || exit "$$?";)
clean:
	rm -f ../plugin/*.so ../plugin/*.cfg
	$(foreach N,$(dirs),make clean -C $(N);)
	rm -f *~


