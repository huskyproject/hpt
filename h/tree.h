/* tree.h - declare structures used by tree.c
 * vix 27jun86 [broken out of tree.c]
 */


#ifndef	_TREE_FLAG
#define	_TREE_FLAG


typedef	struct	tree_s
	{
		struct	tree_s	*tree_l, *tree_r;
		short		tree_b;
		char		*tree_p;
	}
	tree;


#endif	_TREE_FLAG
