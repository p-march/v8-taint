#!/usr/bin/python

import sys, os, math

def Mean(values):
  sum = 0.0
  for val in values: 
    sum += val;
  return sum / len(values)


def GeometricMean(values):
  log = 0.0
  for val in values:
    log += math.log(val)
  return math.pow(math.e, log / len(values))


def StandardDeviation(values):
  sum = 0.0
  mean = Mean(values)
  for val in values: 
    sum += math.pow(mean - val, 2);
  return math.sqrt(sum / len(values))


def main():
  if (len(sys.argv) != 2):
    print 'usage:', os.path.basename(sys.argv[0]), '<input file>'

  f = open(sys.argv[1], 'r');

  dic = {}
  names = []

  for l in f:
    if (len(l.split()) < 2):
      continue
    name = l.split()[0]
    value = l.split()[-1]
    if name[-1] == ':':
      name = name[:-1]
 
    if name not in names:
      names.append(name)
    if (name in dic):
      dic[name].append(float(value))
    else:
      dic[name] = [float(value)]

  score = []
  for i in dic:
    gmean = GeometricMean(dic[i])
    deviation = StandardDeviation(dic[i])
    dic[i] = ('%.0f' % gmean, '%.1f' % (deviation / gmean * 100.0))
    score.append(gmean)

  for i in names:
    print '%10s' % i + '\t' + \
          '%10s' % dic[i][0], \
          '(' + '%4s' % dic[i][1] + '%)'

main()
