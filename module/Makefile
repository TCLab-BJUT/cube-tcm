dirs= key pcr state nv vtcm_hub vtcm_utils vtcm_store vtcm_port vtcm_input vtcm_auto vtcm_manager auth vtcm_switch
all:
	$(foreach N,$(dirs),make -C $(N) || exit "$$?";)
clean:
	rm -f ../plugin/*.so ../plugin/*.cfg
	$(foreach N,$(dirs),make clean -C $(N);)
	rm -f *~


