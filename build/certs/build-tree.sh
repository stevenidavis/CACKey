#! /bin/bash

opt_mode='showcert'

if [ -n "$1" ]; then
	opt_mode="$1"
fi

unset sh_list tree
for cert in *.crt; do
	ih="$(openssl x509 -in "${cert}" -noout -issuer_hash)"
	sh="$(openssl x509 -in "${cert}" -noout -subject_hash)"
	sh_list=("${sh_list[@]}" "${sh} ${cert}")
	tree=("${tree[@]}" "${sh} ${ih}")
done

function subjecthash_to_filename() {
	local hash
	local sh_cert hash_chk cert

	hash="$1"

	for sh_cert in "${sh_list[@]}"; do
		hash_chk="$(echo "${sh_cert}" | cut -f 1 -d ' ')"

		if [ "${hash_chk}" = "${hash}" ]; then
			cert="$(echo "${sh_cert}" | cut -f 2- -d ' ')"

			echo "${cert}"

			return
		fi
	done

	return
}

function print_cert() {
	local cert
	local sh ih i_cert

	cert="$1"
	ih="$(openssl x509 -in "${cert}" -noout -issuer_hash)"
	sh="$(openssl x509 -in "${cert}" -noout -subject_hash)"

	i_cert="$(subjecthash_to_filename "${ih}")"

	if [ "${i_cert}" != "${cert}" ]; then
		print_cert "${i_cert}"
	fi

	echo "${cert}"
}

idx=0
unset certs

for cert in *.crt; do
	print_cert "${cert}"
done | while read cert; do
	is_dupe='0'
	for chk_cert in "${certs[@]}"; do
		if [ "${chk_cert}" = "${cert}" ]; then
			is_dupe='1'

			break
		fi
	done

	if [ "${is_dupe}" = '1' ]; then
		continue
	fi

	certs=("${certs[@]}" "${cert}")

	echo "${cert}"
done | while read cert; do
	case "${opt_mode}" in
		showcert)
			openssl x509 -in "${cert}" -text
			;;
		showfile)
			echo "${cert}"
			;;
		script)
			i_cert="$(subjecthash_to_filename "$(openssl x509 -in "${cert}" -issuer_hash -noout)")"

			s_idx="$(openssl x509 -in "${cert}" -outform der | openssl sha1 | sed 's@.*= *@@' | cut -c 1-10)"
			s_shortsubject="$(openssl x509 -in "${cert}" -subject -noout | sed 's@.*=@@' | cut -c 1-20)"
			s_normsubject="$(echo "${s_shortsubject}" | sed 's@ @@g' | dd conv=lcase 2>/dev/null)"
			s_filename="federal-${s_normsubject}-${s_idx}.crt"

			i_idx="$(openssl x509 -in "${i_cert}" -outform der | openssl sha1 | sed 's@.*= *@@' | cut -c 1-10)"
			i_shortsubject="$(openssl x509 -in "${i_cert}" -subject -noout | sed 's@.*=@@' | cut -c 1-20)"
			i_normsubject="$(echo "${i_shortsubject}" | sed 's@ @@g' | dd conv=lcase 2>/dev/null)"
			i_filename="federal-${i_normsubject}-${i_idx}.crt"

			echo "cat << \_EOF_ > '${s_filename}'"
			openssl x509 -in "${cert}"
			echo "_EOF_"
			echo "# NetScaler: link ssl certKey '${s_shortsubject} ${s_idx}' '${i_shortsubject} ${i_idx}'"
			;;
	esac
done
