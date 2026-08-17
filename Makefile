BIN_DIR  := bin
BINARY   := $(BIN_DIR)/vpn
PKG      := ./cmd/vpn
KEY      := secret.key

XFER_SIZE_MB := 5
XFER_NAME    := data-uji.bin
XFER_A       := transfer/endpoint-a
XFER_B       := transfer/endpoint-b

.PHONY: help build clean genkey fmt vet lab lab-topology lab-down lab-status lab-logs \
        demo-file demo-check demo-clean

help:
	@echo "sister-b2-vpn"
	@echo ""
	@echo "  Program"
	@echo "    make build         build binary ke ./$(BINARY)"
	@echo "    make genkey        buat pre-shared key ./$(KEY)"
	@echo "    make clean         hapus binary, key, dan berkas uji"
	@echo "    make fmt           rapikan format sumber"
	@echo "    make vet           go vet + pemeriksaan format"
	@echo ""
	@echo "  Lab jaringan (butuh root)"
	@echo "    make lab-topology  bangun topologi SAJA, VPN dinyalakan manual  <-- untuk video"
	@echo "    make lab           bangun topologi + jalankan VPN otomatis"
	@echo "    make lab-status    tampilkan alamat dan routing tiap namespace"
	@echo "    make lab-logs      tampilkan log kedua endpoint (mode otomatis)"
	@echo "    make lab-down      bersihkan lab"
	@echo ""
	@echo "  Uji transfer file"
	@echo "    make demo-file     buat $(XFER_SIZE_MB) MB di $(XFER_A)/ (boleh diganti berkas lain, mis. PDF)"
	@echo "    make demo-check    bandingkan SHA-256 semua berkas di $(XFER_A)/ vs $(XFER_B)/"
	@echo "    make demo-clean    kosongkan kedua folder transfer/"
	@echo ""
	@echo "  Alur lengkap ada di README.md bagian Cara Menjalankan"

build:
	@mkdir -p $(BIN_DIR)
	go build -o $(BINARY) $(PKG)
	@echo "binary siap: ./$(BINARY)"

genkey: build
	@test ! -f $(KEY) || (echo "$(KEY) sudah ada; hapus dulu bila ingin key baru" && exit 1)
	./$(BINARY) genkey -out $(KEY)

fmt:
	gofmt -w .

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "berkas berikut belum diformat:"; gofmt -l .; exit 1)

clean: demo-clean
	rm -rf $(BIN_DIR)
	rm -f $(KEY)
	go clean -cache

lab-topology:
	./scripts/netns-lab.sh topology

lab:
	./scripts/netns-lab.sh up

lab-status:
	./scripts/netns-lab.sh status

lab-logs:
	./scripts/netns-lab.sh logs

lab-down:
	./scripts/netns-lab.sh down

demo-file:
	@mkdir -p $(XFER_A) $(XFER_B)
	dd if=/dev/urandom of=$(XFER_A)/$(XFER_NAME) bs=1M count=$(XFER_SIZE_MB) status=none
	@echo ""
	@echo "berkas uji dibuat: $(XFER_A)/$(XFER_NAME)"
	@ls -lh $(XFER_A)/ $(XFER_B)/
	@echo ""
	@echo "SHA-256 sumber:"
	@sha256sum $(XFER_A)/$(XFER_NAME)
	@echo ""
	@echo "Berkas lain (mis. PDF, video) boleh diletakkan langsung di $(XFER_A)/ —"
	@echo "'make demo-check' memeriksa SEMUA berkas di folder ini, bukan cuma $(XFER_NAME)."

demo-check:
	@echo "isi kedua folder:"
	@ls -lh $(XFER_A)/ $(XFER_B)/ 2>/dev/null
	@echo ""
	@found=0; fail=0; \
	for f in $(XFER_A)/*; do \
		[ -f "$$f" ] || continue; \
		found=1; \
		name=$$(basename "$$f"); \
		dst="$(XFER_B)/$$name"; \
		if [ ! -f "$$dst" ]; then \
			echo "GAGAL: $$name belum ada di $(XFER_B)/ (transfer belum berjalan)"; \
			fail=1; continue; \
		fi; \
		src_hash=$$(sha256sum "$$f" | awk '{print $$1}'); \
		dst_hash=$$(sha256sum "$$dst" | awk '{print $$1}'); \
		if [ "$$src_hash" = "$$dst_hash" ]; then \
			echo "LULUS: $$name — checksum identik ($$src_hash)"; \
		else \
			echo "GAGAL: $$name — checksum berbeda"; \
			echo "   sumber  : $$src_hash"; \
			echo "   diterima: $$dst_hash"; \
			fail=1; \
		fi; \
	done; \
	if [ "$$found" -eq 0 ]; then \
		echo "GAGAL: tidak ada berkas di $(XFER_A)/"; exit 1; \
	fi; \
	exit $$fail

demo-clean:
	find $(XFER_A) $(XFER_B) -type f ! -name '.gitkeep' -delete
