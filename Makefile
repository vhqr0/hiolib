.PHONY: compile
compile:
	hy2py -o hiolib hiolib

.PHONY: build
build: compile
	hy setup.hy -v bdist_wheel

.PHONY: clean
clean:
	rm -rf build dist hiolib.egg-info
	hy -c "(do (import pathlib [Path] shutil [rmtree]) \
(for [p (.rglob (Path \"hiolib\") \"*.py\")] (.unlink p)) \
(for [p (.rglob (Path \"hiolib\") \"__pycache__\")] (rmtree p)))"
