# Webminer

An experimental vector-accelerated CPU miner for the Webcash electronic payment network.

Webminer is tested and known to work on recent versions of macOS and Linux.  It is written in a platform-independent style and is likely to work on other operating systems as well.  If you need to make modifications to get it to run in your environment, please consider submitting a pull request on the GitHub repo: https://github.com/maaku/webminer

# Compiling

To compile webminer, you need Google's bazel build tool.  Instructions for installing bazel are available at the official bazel website: https://bazel.build

To build webminer, open a shell and navigate to directory containing the source code and execute this command:

```
bazel build -c opt webminer
```

Bazel will handle the details of fetching and compiling all the necessary dependencies.

# Running

The final built executable will be available at `bazel-bin/webminer`.  Simply run this executable and it will begin mining webcash.

The claim codes for mined webcash will be logged both to the stdout (along with lots of other info), and to a dedicated file named 'webcash.log' in the current directory.  If webcash is successfully generated but there is an error communicating to the server, the relevant information (including both the proof-of-work solution and the claim code) are output to a file named 'orphans.log' in the current directory.  The names of both files can be changed with the `--webcashlog=filename` and `--orphanlog=filename` command line options.  Mined webcash can be inserted into a webcash wallet using the official `walletclient.py` tool:

```
cat webcash.log | xargs python path/to/walletclient.py insert
```

Webminer will automatically spawn mining threads equal to the number of execution units on the machine in which it is running.  To control precisely the number of mining threads, use the `--workers=N` option.

WARNING: Do *NOT* execute webminer with with `bazel run`!  Webminer will generate files to store the claim codes for any webcash generated, which will be destroyed along with the temporary sandbox created by `bazel run`.

# License

This repository and its source code is distributed under the terms of the Mozilla Public License 2.0.  See MPL-2.0.txt.
