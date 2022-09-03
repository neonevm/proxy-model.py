python -c "import sys; print(sys.path)"
pip3 install --upgrade pip
pip3 install -r requirements.txt
yes | cp -i log_cfg_fuzzing.json log_cfg.json
ls -l $SRC
git rev-parse HEAD
cd $SRC
for fuzzer in $(find $SRC -name 'fuzz_*.py'); do
  compile_python_fuzzer $fuzzer
done
