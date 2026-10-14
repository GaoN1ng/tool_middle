import unittest
import numpy as np
from learn import choose_threshold,probabilities
from sklearn.ensemble import RandomForestClassifier

class LearningContract(unittest.TestCase):
 def test_file_fp_constraint_disables_unseparable_class(self):
  result=choose_threshold(np.array([.8,.8,.9]),np.array([True,False,False]),np.ones(3,dtype=bool),.005)
  self.assertTrue(result['disabled']);self.assertEqual(result['tp'],0);self.assertEqual(result['fn'],1)
 def test_unknown_truth_is_excluded_and_equal_scores_have_one_decision(self):
  result=choose_threshold(np.array([.9,.8,.95]),np.array([True,False,False]),np.array([True,True,False]),.005)
  self.assertEqual(result['tp'],1);self.assertEqual(result['fp'],0);self.assertLessEqual(result['threshold'],.9)
 def test_fold_with_no_positive_class_returns_zero(self):
  model=RandomForestClassifier(n_estimators=4,random_state=1).fit([[0],[1],[2]],[[0,1],[0,0],[0,1]])
  p=probabilities(model,np.array([[1],[2]]));self.assertEqual(p.shape,(2,2));self.assertTrue((p[:,0]==0).all())
if __name__=='__main__':unittest.main()
