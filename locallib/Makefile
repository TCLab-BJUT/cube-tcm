dirs= src/auth src/io src/key_manage src/vtcm_alg src/vtcm_ex_alg
all:
	$(foreach N,$(dirs),make -C $(N);)
clean:
	rm -f bin/*.so 
	$(foreach N,$(dirs),make clean -C $(N);)


