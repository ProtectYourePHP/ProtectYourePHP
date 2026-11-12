/* Argument information for pyp.stub.php - keep both files in sync. */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_pyp_macs, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

#define arginfo_pyp_ext_info arginfo_pyp_macs

ZEND_FUNCTION(pyp_macs);
ZEND_FUNCTION(pyp_ext_info);

static const zend_function_entry ext_functions[] = {
	ZEND_FE(pyp_macs, arginfo_pyp_macs)
	ZEND_FE(pyp_ext_info, arginfo_pyp_ext_info)
	ZEND_FE_END
};
