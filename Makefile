SHELL      := /bin/bash
PYTHON     ?= python3

REPROAPK   ?= repro-apk
INPLACEFIX ?= repro-apk-inplace-fix

PYCOV      := $(PYTHON) -mcoverage run --data-file=$(PWD)/.coverage --source $(PWD)

DOCTEST    := binres.py diff-zip-meta.py fix-compresslevel.py fix-files.py fix-newlines.py \
              inplace-fix.py list-compresslevel.py rm-files.py zipalignment.py zipinfo.py

export PYTHONWARNINGS := default

.PHONY: all install test test-cli doctest coverage test-examples lint lint-extra clean cleanup

all:

install:
	$(PYTHON) -mpip install -e .

test: test-cli doctest lint lint-extra

test-cli:
	# TODO
	$(REPROAPK) --version

doctest:
	# NB: uses test/ & requires zipalign on $$PATH
	TZ=UTC $(PYTHON) -m doctest $(DOCTEST)

coverage:
	# NB: uses test/ & requires zipalign on $$PATH
	TZ=UTC $(PYCOV) -m doctest $(DOCTEST)
	for py in *.py; do [ -x "$$py" ] && $(PYCOV) -a "$$py" --help; done
	$(MAKE) test-examples \
	  REPROAPK="$(PYCOV) -a -m repro_apk.__init__" \
	  INPLACEFIX="$(PYCOV) -a -m repro_apk.inplace_fix"
	$(MAKE) test-examples \
	  REPROAPK="$(PWD)/test/pycov.sh $(PYTHON) $(PWD) $(REPROAPK)" \
	  INPLACEFIX="$(PWD)/test/pycov.sh $(PYTHON) $(PWD) $(INPLACEFIX)"
	$(PYTHON) -mcoverage html --data-file=$(PWD)/.coverage
	$(PYTHON) -mcoverage report --data-file=$(PWD)/.coverage

test-examples:
	mkdir -p .tmp
	# fix-compresslevel
	$(REPROAPK) fix-compresslevel test/data/level6.apk .tmp/level6-to-9.apk 9 'LICENSE.*'
	zipalign -f 4 .tmp/level6-to-9.apk .tmp/level6-to-9-aligned.apk
	cmp test/data/level9.apk .tmp/level6-to-9-aligned.apk
	$(REPROAPK) fix-compresslevel test/data/level9.apk .tmp/level9-to-6.apk 6 'LICENSE.*'
	zipalign -f 4 .tmp/level9-to-6.apk .tmp/level9-to-6-aligned.apk
	cmp test/data/level6.apk .tmp/level9-to-6-aligned.apk
	# fix-files (& fix-compresslevel)
	$(REPROAPK) fix-files test/data/unix.apk .tmp/unix2dos.apk unix2dos 'LICENSE.*'
	zipalign -f 4 .tmp/unix2dos.apk .tmp/unix2dos-aligned.apk
	cmp test/data/crlf.apk .tmp/unix2dos-aligned.apk
	$(REPROAPK) fix-files test/data/test-unix.zip .tmp/unix2dos.zip unix2dos '*'
	! cmp test/data/test-dos.zip .tmp/unix2dos.zip
	$(REPROAPK) fix-compresslevel .tmp/unix2dos.zip .tmp/unix2dos-fixed.zip 6 test
	cmp test/data/test-dos.zip .tmp/unix2dos-fixed.zip
	$(REPROAPK) fix-files test/data/test-unix.zip .tmp/unix2dos-l6.zip unix2dos '*' \
	  --compresslevel '*:6'
	cmp test/data/test-dos.zip .tmp/unix2dos-l6.zip
	# fix-newlines (& fix-compresslevel)
	$(REPROAPK) fix-newlines test/data/unix.apk .tmp/unix-to-crlf.apk 'LICENSE.*'
	zipalign -f 4 .tmp/unix-to-crlf.apk .tmp/unix-to-crlf-aligned.apk
	cmp test/data/crlf.apk .tmp/unix-to-crlf-aligned.apk
	$(REPROAPK) fix-newlines --from-crlf test/data/crlf.apk .tmp/crlf-to-unix.apk 'LICENSE.*'
	zipalign -f 4 .tmp/crlf-to-unix.apk .tmp/crlf-to-unix-aligned.apk
	cmp test/data/unix.apk .tmp/crlf-to-unix-aligned.apk
	$(REPROAPK) fix-newlines test/data/test-unix.zip .tmp/lf2crlf.zip '*'
	! cmp test/data/test-dos.zip .tmp/lf2crlf.zip
	$(REPROAPK) fix-compresslevel .tmp/lf2crlf.zip .tmp/lf2crlf-fixed.zip 6 test
	cmp test/data/test-dos.zip .tmp/lf2crlf-fixed.zip
	$(REPROAPK) fix-newlines test/data/test-unix.zip .tmp/lf2crlf-l6.zip '*' \
	  --compresslevel '*:6'
	cmp test/data/test-dos.zip .tmp/lf2crlf-l6.zip
	# fix-newlines via repro-apk-inplace-fix
	cp test/data/unix.apk .tmp/unix-to-crlf-inplace.apk
	$(INPLACEFIX) --zipalign fix-newlines .tmp/unix-to-crlf-inplace.apk 'LICENSE.*'
	cmp test/data/crlf.apk .tmp/unix-to-crlf-inplace.apk
	cp test/data/unix.apk .tmp/unix-to-crlf-inplace-p.apk
	$(INPLACEFIX) --page-align fix-newlines .tmp/unix-to-crlf-inplace-p.apk 'LICENSE.*'
	cmp test/data/crlf-p.apk .tmp/unix-to-crlf-inplace-p.apk
	cp test/data/unix.apk .tmp/unix-to-crlf-inplace-P16.apk
	$(INPLACEFIX) --internal --page-size 16 fix-newlines \
	  .tmp/unix-to-crlf-inplace-P16.apk 'LICENSE.*'
	cmp test/data/crlf-P16.apk .tmp/unix-to-crlf-inplace-P16.apk
	# rm-files (via repro-apk-inplace-fix as well)
	$(REPROAPK) rm-files test/data/baseline1.profm.apk .tmp/rm1.apk '*.profm'
	cp test/data/baseline2.profm.apk .tmp/rm2.apk
	$(INPLACEFIX) rm-files .tmp/rm2.apk '*.profm'
	cmp .tmp/rm1.apk .tmp/rm2.apk
	# sort-apk
	$(REPROAPK) sort-apk test/data/golden-aligned-in.apk .tmp/sorted.apk
	cmp test/data/golden-aligned-in-sorted.apk .tmp/sorted.apk
	$(REPROAPK) sort-apk --no-realign --reset-lh-extra test/data/golden-aligned-in.apk \
	  .tmp/sorted-noalign.apk
	cmp test/data/golden-aligned-in-sorted-noalign.apk .tmp/sorted-noalign.apk
	# sort-baseline
	$(REPROAPK) sort-baseline test/data/baseline1.profm .tmp/baseline1-sorted.profm
	cmp test/data/baseline2.profm .tmp/baseline1-sorted.profm
	# sort-baseline via repro-apk-inplace-fix
	cp test/data/baseline1.profm .tmp/baseline1-inplace.profm
	$(INPLACEFIX) sort-baseline .tmp/baseline1-inplace.profm
	cmp test/data/baseline2.profm .tmp/baseline1-inplace.profm
	# sort-baseline --apk
	$(REPROAPK) sort-baseline --apk test/data/baseline1.profm.apk \
	  .tmp/baseline1.profm-sorted.apk
	zipalign -f 4 .tmp/baseline1.profm-sorted.apk .tmp/baseline1.profm-sorted-aligned.apk
	cmp test/data/baseline2.profm.apk .tmp/baseline1.profm-sorted-aligned.apk
	# sort-baseline --apk via repro-apk-inplace-fix
	cp test/data/baseline1.profm.apk .tmp/baseline1.profm-inplace.apk
	$(INPLACEFIX) --zipalign sort-baseline --apk .tmp/baseline1.profm-inplace.apk
	cmp test/data/baseline2.profm.apk .tmp/baseline1.profm-inplace.apk
	# binres dump axml
	cd test/data && diff -Naur AndroidManifest.xml.brdump \
	  <( $(REPROAPK) binres dump AndroidManifest.xml -q )
	cd test/data && diff -Naur AndroidManifest.xml.brxml \
	  <( $(REPROAPK) binres dump AndroidManifest.xml --xml -q )
	cd test/data && diff -Naur AndroidManifest.xml.json \
	  <( $(REPROAPK) binres dump AndroidManifest.xml --json -q )
	cd test/data && diff -Naur resource.xml.brdump \
	  <( $(REPROAPK) binres dump resource.xml -q )
	cd test/data && diff -Naur resource.xml.brxml \
	  <( $(REPROAPK) binres dump resource.xml --xml -q )
	cd test/data && diff -Naur resource.xml.json \
	  <( $(REPROAPK) binres dump resource.xml --json -q )
	# binres dump axml --apk
	cd test/data && diff -Naur AndroidManifest.xml.brdump \
	  <( $(REPROAPK) binres dump --apk baseline1.profm.apk AndroidManifest.xml -q )
	cd test/data && diff -Naur AndroidManifest.xml.brxml \
	  <( $(REPROAPK) binres dump --apk baseline2.profm.apk AndroidManifest.xml --xml -q )
	# binres dump arsc
	cd test/data && diff -Naur resources1.arsc.brdump \
	  <( $(REPROAPK) binres dump resources1.arsc -q )
	cd test/data && diff -Naur resources1.arsc.json \
	  <( $(REPROAPK) binres dump resources1.arsc --json -q )
	cd test/data && diff -Naur resources2.arsc.brdump \
	  <( $(REPROAPK) binres dump resources2.arsc -q )
	cd test/data && diff -Naur resources2.arsc.json \
	  <( $(REPROAPK) binres dump resources2.arsc --json -q )
	# binres dump arsc --apk
	cd test/data && diff -Naur golden-aligned-in-arsc.brdump \
	  <( $(REPROAPK) binres dump --apk golden-aligned-in.apk resources.arsc )
	# binres fastid
	cd test/data && diff -Naur <( echo "android.appsecurity.cts.tinyapp 10 1.0" ) \
	  <( $(REPROAPK) binres fastid --short unix.apk )
	# binres fastperms
	cd test/data && diff -Naur perms.apk.perms \
	  <( $(REPROAPK) binres fastperms perms.apk -q )
	# binres manifest-info
	cd test/data && diff -Naur golden-aligned-in.apk.json \
	  <( $(REPROAPK) binres manifest-info golden-aligned-in.apk )
	cd test/data && diff -Naur perms.apk.json \
	  <( $(REPROAPK) binres manifest-info perms.apk )
	# diff-zip-meta
	cd test/data && diff -Naur golden-aligned-in-sorted.diff \
	  <( $(REPROAPK) diff-zip-meta golden-aligned-in.apk golden-aligned-in-sorted.apk )
	cd test/data && diff -Naur golden-aligned-in-sorted-no-lfh-ord-off.diff \
	  <( $(REPROAPK) diff-zip-meta golden-aligned-in.apk golden-aligned-in-sorted.apk \
	     --no-lfh-extra --no-offsets --no-ordering )
	cd test/data && diff -Naur golden-aligned-in-sorted-noalign.diff \
	  <( $(REPROAPK) diff-zip-meta golden-aligned-in-sorted.apk \
	     golden-aligned-in-sorted-noalign.apk )
	cd test/data && diff -Naur level6-9.diff \
	  <( $(REPROAPK) diff-zip-meta level6.apk level9.apk )
	cd test/data && diff -Naur unix-crlf.diff \
	  <( $(REPROAPK) diff-zip-meta unix.apk crlf.apk )
	cd test/data && diff -Naur unix-6-no-off.diff \
	  <( $(REPROAPK) diff-zip-meta unix.apk level6.apk --no-offsets )
	cd test/data && diff -Naur atime1-2.diff \
	  <( $(REPROAPK) diff-zip-meta atime1.zip atime2.zip )
	# dump-arsc
	cd test/data && diff -Naur resources1.arsc.dump \
	  <( $(REPROAPK) dump-arsc resources1.arsc )
	cd test/data && diff -Naur resources2.arsc.dump \
	  <( $(REPROAPK) dump-arsc resources2.arsc )
	# dump-arsc --apk
	cd test/data && diff -Naur golden-aligned-in-arsc.dump \
	  <( $(REPROAPK) dump-arsc --apk crlf.apk )
	# dump-axml
	cd test/data && diff -Naur AndroidManifest.xml.dump \
	  <( $(REPROAPK) dump-axml AndroidManifest.xml )
	cd test/data && diff -Naur main.xml.dump \
	  <( $(REPROAPK) dump-axml main.xml )
	# dump-axml --apk
	cd test/data && diff -Naur golden-aligned-in-axml.dump \
	  <( $(REPROAPK) dump-axml --apk golden-aligned-in.apk AndroidManifest.xml )
	# dump-baseline .prof
	cd test/data && diff -Naur <( gunzip < baseline1.prof.dump.gz ) \
	  <( $(REPROAPK) dump-baseline -v baseline1.prof )
	cd test/data && diff -Naur <( gunzip < baseline2.prof.dump.gz ) \
	  <( $(REPROAPK) dump-baseline -v baseline2.prof )
	# dump-baseline .profm
	cd test/data && diff -Naur baseline1.profm.dump \
	  <( $(REPROAPK) dump-baseline -v baseline1.profm )
	cd test/data && diff -Naur baseline2.profm.dump \
	  <( $(REPROAPK) dump-baseline -v baseline2.profm )
	# dump-baseline --apk .prof
	# TODO
	# dump-baseline --apk .profm
	cd test/data && diff -Naur \
	  <( echo entry=assets/dexopt/baseline.profm; cat baseline1.profm.dump ) \
	  <( $(REPROAPK) dump-baseline --apk -v baseline1.profm.apk )
	cd test/data && diff -Naur \
	  <( echo entry=assets/dexopt/baseline.profm; cat baseline2.profm.dump ) \
	  <( $(REPROAPK) dump-baseline --apk -v baseline2.profm.apk )
	# list-compresslevel
	cd test/data && diff -Naur level6.levels \
	  <( $(REPROAPK) list-compresslevel level6.apk )
	cd test/data && diff -Naur level9.levels \
	  <( $(REPROAPK) list-compresslevel level9.apk )
	cd test/data && diff -Naur <( echo "filename='LICENSE.GPLv3' compresslevel=6" ) \
	  <( $(REPROAPK) list-compresslevel unix.apk LICENSE.GPLv3 )
	cd test/data && diff -Naur <( echo "filename='test' compresslevel=9|6" ) \
	  <( $(REPROAPK) list-compresslevel test-unix.zip )
	cd test/data && diff -Naur <( echo "filename='test' compresslevel=6|4|1" ) \
	  <( $(REPROAPK) list-compresslevel test-dos.zip )
	cd test/data && diff -Naur <( echo "filename='test' compresslevel=6" ) \
	  <( $(REPROAPK) list-compresslevel test-dos.zip --levels 6,9 )
	# zipalign
	$(REPROAPK) zipalign .tmp/level6-to-9.apk .tmp/level6-to-9-aligned-py.apk
	cmp .tmp/level6-to-9-aligned.apk .tmp/level6-to-9-aligned-py.apk
	$(REPROAPK) zipalign .tmp/level9-to-6.apk .tmp/level9-to-6-aligned-py.apk
	cmp .tmp/level9-to-6-aligned.apk .tmp/level9-to-6-aligned-py.apk
	$(REPROAPK) zipalign .tmp/unix2dos.apk .tmp/unix2dos-aligned-py.apk
	cmp .tmp/unix2dos-aligned.apk .tmp/unix2dos-aligned-py.apk
	$(REPROAPK) zipalign .tmp/unix-to-crlf.apk .tmp/unix-to-crlf-aligned-py.apk
	cmp .tmp/unix-to-crlf-aligned.apk .tmp/unix-to-crlf-aligned-py.apk
	$(REPROAPK) zipalign .tmp/crlf-to-unix.apk .tmp/crlf-to-unix-aligned-py.apk
	cmp .tmp/crlf-to-unix-aligned.apk .tmp/crlf-to-unix-aligned-py.apk
	$(REPROAPK) zipalign .tmp/baseline1.profm-sorted.apk .tmp/baseline1.profm-sorted-aligned-py.apk
	cmp .tmp/baseline1.profm-sorted-aligned.apk .tmp/baseline1.profm-sorted-aligned-py.apk
	set -e; for apk in test/data/*.apk; do echo "$$apk"; \
	  zipalign -f 4 "$$apk" .tmp/aligned.apk; \
	  $(REPROAPK) zipalign "$$apk" .tmp/aligned-py.apk; \
	  cmp .tmp/aligned.apk .tmp/aligned-py.apk; \
	done
	# zipalignment
	cd test/data && diff -Naur zipalignment <( $(REPROAPK) zipalignment *.apk )
	# zipinfo
	set -e; cd test/data && for apk in *.apk; do echo "$$apk"; \
	  diff -Naur <( zipinfo    "$$apk" ) <( $(REPROAPK) zipinfo    "$$apk" ); \
	  diff -Naur <( zipinfo -l "$$apk" ) <( $(REPROAPK) zipinfo -l "$$apk" ); \
	done

lint:
	set -x; flake8 repro_apk/*.py
	set -x; pylint repro_apk/*.py

lint-extra:
	set -x; mypy --strict --disallow-any-unimported repro_apk/*.py

clean: cleanup
	rm -fr repro_apk.egg-info/

cleanup:
	find -name '*~' -delete -print
	rm -fr __pycache__/ repro_apk/__pycache__/ .mypy_cache/
	rm -fr build/ dist/
	rm -fr .coverage htmlcov/
	rm -fr .tmp/

.PHONY: _package _publish

_package:
	SOURCE_DATE_EPOCH="$$( git log -1 --pretty=%ct )" \
	  $(PYTHON) setup.py sdist bdist_wheel
	twine check dist/*

_publish: cleanup _package
	read -r -p "Are you sure? "; \
	[[ "$$REPLY" == [Yy]* ]] && twine upload dist/*
